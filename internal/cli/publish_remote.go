package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

type remoteObservation struct {
	parent           *pub.TargetGeneration
	resumeGeneration *pub.TargetGeneration
	resumeCheckpoint *pub.Checkpoint
	resumeLock       *pub.GenerationLock
	expected         pub.ParentExpectation
	oldManifestPath  string
}

func (client *publishTargetClient) getControl(ctx context.Context, key string) (pub.ControlObject, error) {
	if client == nil {
		return pub.ControlObject{}, errors.New("nil publish target client")
	}
	if client.r2 != nil {
		return client.r2.R2GetControl(ctx, key)
	}
	if client.cos != nil {
		return client.cos.COSGetControl(ctx, key)
	}
	return pub.ControlObject{}, errors.New("publish target client has no provider")
}

func (client *publishTargetClient) publisher(root, journalDir string) (*pub.Publisher, error) {
	source := pub.DirectorySource{Root: root}
	if client == nil {
		return nil, errors.New("nil publish target client")
	}
	if client.r2 != nil {
		publisher := pub.NewR2CloudflarePublisher(client.r2, source, journalDir, pub.Hooks{}).WithRequiredPurgeEvidence()
		if client.deleteMode == config.StorageDeleteCheckpointFenced {
			publisher = publisher.WithCheckpointFencedDeletion()
		}
		return publisher, nil
	}
	if client.cos != nil {
		publisher := pub.NewCOSEdgeOnePublisher(client.cos, source, journalDir, pub.Hooks{}).WithRequiredPurgeEvidence()
		if client.deleteMode == config.StorageDeleteCheckpointFenced {
			publisher = publisher.WithCheckpointFencedDeletion()
		}
		return publisher, nil
	}
	return nil, errors.New("publish target client has no provider")
}

func observeRemoteTarget(ctx context.Context, canonical *state.Store, client *publishTargetClient, target, txDir string) (remoteObservation, error) {
	return observeRemoteTargetMode(ctx, canonical, client, target, txDir, true)
}

// observeRemoteTargetControl validates the small canonical/remote control
// plane without copying or hashing the potentially very large content
// manifest. It is used only by the no-change preflight: a positive result also
// requires the selected canonical ref commits and configuration digest to be
// identical to the already committed generation. Any mismatch falls back to
// the full manifest/materialization path below.
func observeRemoteTargetControl(ctx context.Context, canonical *state.Store, client *publishTargetClient, target, txDir string) (remoteObservation, error) {
	return observeRemoteTargetMode(ctx, canonical, client, target, txDir, false)
}

func observeRemoteTargetMode(ctx context.Context, canonical *state.Store, client *publishTargetClient, target, txDir string, includeManifest bool) (remoteObservation, error) {
	observation := remoteObservation{oldManifestPath: filepath.Join(txDir, "old-"+target+".tsv")}
	localGeneration, localGenerationBody, generationExists, err := readLocalTargetGeneration(canonical, target)
	if err != nil {
		return observation, err
	}
	localCheckpoint, localCheckpointBody, checkpointExists, err := readLocalTargetCheckpoint(canonical, target)
	if err != nil {
		return observation, err
	}
	localCheckpointETag, checkpointETagExists, err := readLocalTargetCheckpointETag(canonical, target)
	if err != nil {
		return observation, err
	}
	if generationExists != checkpointExists || generationExists != checkpointETagExists {
		return observation, fmt.Errorf("%w: local target %s generation/checkpoint/ETag closure is incomplete", pub.ErrDrift, target)
	}
	if generationExists {
		if err := validateLocalRemoteRefs(canonical, target, localGeneration); err != nil {
			return observation, err
		}
		if err := validateLocalChannelState(canonical, target, localGeneration); err != nil {
			return observation, err
		}
		if localCheckpoint.Phase != pub.PhaseCheckpointCommitted || localCheckpoint.Generation != localGeneration.Generation || !pub.SamePublicationIntent(localCheckpoint.IntentView, localCheckpoint.IntentSnapshot, localGeneration.IntentView, localGeneration.IntentSnapshot) || localCheckpoint.GenerationSHA256 != digestBytesCLI(localGenerationBody) || localCheckpoint.ContentManifestSHA256 != localGeneration.ContentManifestSHA256 {
			return observation, fmt.Errorf("%w: local target %s checkpoint disagrees with generation", pub.ErrDrift, target)
		}
		observation.parent = &localGeneration
		observation.expected = pub.ParentExpectation{
			Exists: true, Generation: localGeneration.Generation,
			CheckpointSHA256: digestBytesCLI(localCheckpointBody), ETag: localCheckpointETag,
		}
	}
	if includeManifest {
		if err := copyLocalTargetManifest(canonical, target, observation.oldManifestPath, generationExists); err != nil {
			return observation, err
		}
		if generationExists {
			digest, err := hashRegularPath(observation.oldManifestPath)
			if err != nil || digest != localGeneration.ContentManifestSHA256 {
				return observation, fmt.Errorf("%w: local target %s content manifest hash mismatch", pub.ErrDrift, target)
			}
		}
	}
	remoteCheckpointObject, err := client.getControl(ctx, pub.CheckpointKey)
	if err != nil {
		return observation, err
	}
	if !remoteCheckpointObject.Exists {
		if generationExists {
			return observation, fmt.Errorf("%w: remote target %s checkpoint disappeared", pub.ErrDrift, target)
		}
		return observeCOSNextLock(ctx, client, target, 0, observation)
	}
	if remoteCheckpointObject.ETag == "" {
		return observation, fmt.Errorf("%w: remote target %s checkpoint has no ETag", pub.ErrCapability, target)
	}
	remoteCheckpoint, err := pub.DecodeCheckpoint(remoteCheckpointObject.Body)
	if err != nil || string(remoteCheckpoint.Target) != target {
		return observation, fmt.Errorf("%w: invalid remote target %s checkpoint: %v", pub.ErrDrift, target, err)
	}
	localGenerationNumber := uint64(0)
	if generationExists {
		localGenerationNumber = localGeneration.Generation
	}
	switch remoteCheckpoint.Phase {
	case pub.PhaseLocked:
		if remoteCheckpoint.ParentGeneration != localGenerationNumber || remoteCheckpoint.Generation != localGenerationNumber+1 {
			return observation, fmt.Errorf("%w: target %s locked generation is not the next local generation", pub.ErrDrift, target)
		}
		observation.resumeCheckpoint = &remoteCheckpoint
		return observation, nil
	case pub.PhaseCheckpointCommitted:
		generationKey, keyErr := pub.GenerationKey(remoteCheckpoint.Generation)
		if keyErr != nil {
			return observation, keyErr
		}
		remoteGenerationObject, getErr := client.getControl(ctx, generationKey)
		if getErr != nil || !remoteGenerationObject.Exists {
			return observation, fmt.Errorf("%w: target %s immutable generation is unavailable: %v", pub.ErrDrift, target, getErr)
		}
		remoteGeneration, decodeErr := pub.DecodeTargetGeneration(remoteGenerationObject.Body)
		if decodeErr != nil || string(remoteGeneration.Target) != target || digestBytesCLI(remoteGenerationObject.Body) != remoteCheckpoint.GenerationSHA256 || remoteGeneration.Generation != remoteCheckpoint.Generation || !pub.SamePublicationIntent(remoteGeneration.IntentView, remoteGeneration.IntentSnapshot, remoteCheckpoint.IntentView, remoteCheckpoint.IntentSnapshot) || remoteGeneration.ContentManifestSHA256 != remoteCheckpoint.ContentManifestSHA256 || remoteGeneration.DesiredCommit != remoteCheckpoint.DesiredCommit {
			return observation, fmt.Errorf("%w: target %s generation/checkpoint closure is invalid: %v", pub.ErrDrift, target, decodeErr)
		}
		switch remoteGeneration.Generation {
		case localGenerationNumber:
			if !generationExists || !bytes.Equal(localGenerationBody, remoteGenerationObject.Body) || !bytes.Equal(localCheckpointBody, remoteCheckpointObject.Body) || remoteCheckpointObject.ETag != localCheckpointETag {
				return observation, fmt.Errorf("%w: target %s local and remote generation differ", pub.ErrDrift, target)
			}
			observation.expected.CheckpointSHA256 = digestBytesCLI(remoteCheckpointObject.Body)
			return observeCOSNextLock(ctx, client, target, localGenerationNumber, observation)
		case localGenerationNumber + 1:
			observation.resumeGeneration = &remoteGeneration
			observation.resumeCheckpoint = &remoteCheckpoint
			return observation, nil
		default:
			return observation, fmt.Errorf("%w: target %s remote generation %d cannot resume local generation %d", pub.ErrDrift, target, remoteGeneration.Generation, localGenerationNumber)
		}
	default:
		return observation, fmt.Errorf("%w: unsupported target %s checkpoint phase %s", pub.ErrDrift, target, remoteCheckpoint.Phase)
	}
}

func observeCOSNextLock(ctx context.Context, client *publishTargetClient, target string, parentGeneration uint64, observation remoteObservation) (remoteObservation, error) {
	if target != string(pub.TargetTencent) {
		return observation, nil
	}
	lockKey, err := pub.GenerationLockKey(parentGeneration + 1)
	if err != nil {
		return observation, err
	}
	lockObject, err := client.getControl(ctx, lockKey)
	if err != nil {
		return observation, err
	}
	if !lockObject.Exists {
		return observation, nil
	}
	if lockObject.ETag == "" {
		return observation, fmt.Errorf("%w: COS generation lock %s has no ETag", pub.ErrCapability, lockKey)
	}
	lock, err := pub.DecodeGenerationLock(lockObject.Body)
	if err != nil || lock.Generation != parentGeneration+1 || lock.ParentGeneration != parentGeneration || lock.ParentCheckpointSHA256 != observation.expected.CheckpointSHA256 {
		return observation, fmt.Errorf("%w: invalid COS generation lock %s: %v", pub.ErrDrift, lockKey, err)
	}
	observation.resumeLock = &lock
	return observation, nil
}

func validateLocalChannelState(canonical *state.Store, target string, generation pub.TargetGeneration) error {
	for _, channel := range generation.Channels {
		expected, err := channel.CanonicalBody()
		if err != nil {
			return err
		}
		canonicalPath := remoteStatePath(target, filepath.ToSlash(filepath.Join("channels", channel.View, channel.Repo, channel.OS, channel.Arch+".json")))
		actual, exists, err := readOptionalCanonical(canonical, canonicalPath)
		if err != nil || !exists || !bytes.Equal(actual, expected) || digestBytesCLI(actual) != channel.BodySHA256 {
			return fmt.Errorf("%w: local target %s channel %s is incomplete", pub.ErrDrift, target, channel.RemoteKey)
		}
	}
	return nil
}

func readLocalTargetGeneration(canonical *state.Store, target string) (pub.TargetGeneration, []byte, bool, error) {
	body, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "generation.json"))
	if err != nil || !exists {
		return pub.TargetGeneration{}, nil, exists, err
	}
	generation, err := pub.DecodeTargetGeneration(body)
	if err != nil || string(generation.Target) != target {
		return pub.TargetGeneration{}, nil, true, fmt.Errorf("decode local target %s generation: %w", target, err)
	}
	return generation, body, true, nil
}

func readLocalTargetCheckpoint(canonical *state.Store, target string) (pub.Checkpoint, []byte, bool, error) {
	body, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "checkpoint.json"))
	if err != nil || !exists {
		return pub.Checkpoint{}, nil, exists, err
	}
	checkpoint, err := pub.DecodeCheckpoint(body)
	if err != nil || string(checkpoint.Target) != target {
		return pub.Checkpoint{}, nil, true, fmt.Errorf("decode local target %s checkpoint: %w", target, err)
	}
	return checkpoint, body, true, nil
}

func readLocalTargetCheckpointETag(canonical *state.Store, target string) (string, bool, error) {
	body, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "checkpoint.etag"))
	if err != nil || !exists {
		return "", exists, err
	}
	etag := string(body)
	if err := validateCheckpointETag(etag); err != nil {
		return "", true, fmt.Errorf("%w: invalid local target %s checkpoint ETag: %v", pub.ErrDrift, target, err)
	}
	return etag, true, nil
}

func validateCheckpointETag(etag string) error {
	if etag == "" {
		return errors.New("checkpoint ETag is empty")
	}
	if len(etag) > 1024 || strings.ContainsAny(etag, "\x00\r\n\t") {
		return errors.New("checkpoint ETag contains unsafe bytes")
	}
	return nil
}

func readOptionalCanonical(canonical *state.Store, path string) ([]byte, bool, error) {
	file, err := canonical.OpenPath(path)
	if errors.Is(err, os.ErrNotExist) || err != nil && strings.Contains(err.Error(), "no such file or directory") {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, 16<<20+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, false, errors.Join(readErr, closeErr)
	}
	if len(body) > 16<<20 {
		return nil, false, errors.New("canonical remote state file exceeds safety limit")
	}
	return body, true, nil
}

func copyLocalTargetManifest(canonical *state.Store, target, destination string, generationExists bool) error {
	file, err := canonical.OpenPath(remoteStatePath(target, "content.tsv"))
	if err != nil {
		if generationExists {
			return err
		}
		empty, createErr := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return createErr
		}
		return errors.Join(empty.Sync(), empty.Close())
	}
	destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		file.Close()
		return err
	}
	_, copyErr := io.Copy(destinationFile, file)
	return errors.Join(copyErr, file.Close(), destinationFile.Sync(), destinationFile.Close())
}

func validateLocalRemoteRefs(canonical *state.Store, target string, generation pub.TargetGeneration) error {
	for _, ref := range generation.Refs {
		remoteRef, err := desiredToRemoteRef(target, ref.Name)
		if err != nil {
			return err
		}
		actual, exists, err := canonical.Ref(remoteRef)
		if err != nil || !exists || actual.String() != ref.Commit {
			return fmt.Errorf("%w: local remote ref %s does not name %s", pub.ErrDrift, remoteRef, ref.Commit)
		}
	}
	return nil
}

func desiredToRemoteRef(target, desired string) (plumbing.ReferenceName, error) {
	prefix := ""
	switch {
	case strings.HasPrefix(desired, "refs/sow/views/"):
		prefix = "refs/sow/views/"
	case strings.HasPrefix(desired, "refs/sow/snapshots/"):
		prefix = "refs/sow/snapshots/"
	default:
		return "", fmt.Errorf("unsupported desired publication ref %q", desired)
	}
	parts := strings.Split(strings.TrimPrefix(desired, prefix), "/")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid desired publication ref %q", desired)
	}
	return state.RemoteRef(target, parts[0], parts[1], parts[2], parts[3])
}

func remoteStatePath(target, filename string) string {
	return filepath.ToSlash(filepath.Join("remotes", target, filename))
}

func remoteIntentStatePath(target, intentView, intentSnapshot, filename string) (string, error) {
	if err := pub.ValidatePublicationIntent(intentView, intentSnapshot); err != nil {
		return "", err
	}
	var scope string
	if intentView == "snapshot" {
		scope = filepath.ToSlash(filepath.Join("intents", "snapshots", intentSnapshot))
	} else {
		scope = filepath.ToSlash(filepath.Join("intents", "views", intentView))
	}
	return remoteStatePath(target, filepath.ToSlash(filepath.Join(scope, filename))), nil
}

func digestBytesCLI(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func hashRegularPath(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
