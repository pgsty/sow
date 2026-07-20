package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

type canonicalServingChannel struct {
	Path    string
	Channel serving.Channel
}

type canonicalServingGeneration struct {
	Coordinate   serving.GenerationCoordinate
	JSONPath     string
	ManifestPath string
	Generation   serving.Generation
}

type canonicalServingRetiredGeneration struct {
	JSONPath     string
	ManifestPath string
	Retired      serving.RetiredGeneration
}

type canonicalServingLifecycle struct {
	Channels    []canonicalServingChannel
	Targets     map[string]serving.TargetIdentity
	Generations map[string]canonicalServingGeneration
	Retired     map[string]canonicalServingRetiredGeneration
}

func loadCanonicalServingChannelIndex(canonical *state.Store) ([]canonicalServingChannel, map[string]serving.TargetIdentity, error) {
	targets := make(map[string]serving.TargetIdentity)
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return nil, targets, err
	}
	paths, err := canonical.ListFilesAt(head, "serving/yum/")
	if err != nil {
		return nil, targets, err
	}
	var channels []canonicalServingChannel
	for _, canonicalPath := range paths {
		switch {
		case isTargetStatePath(canonicalPath):
			body, err := readCanonicalLifecyclePath(canonical, canonicalPath)
			if err != nil {
				return nil, nil, err
			}
			target, err := decodeAnyServingTarget(body)
			if err != nil || serving.TargetStatePath(target) != canonicalPath {
				return nil, nil, errors.Join(err, fmt.Errorf("canonical serving target path %s does not match body", canonicalPath))
			}
			if _, exists := targets[target.ID]; exists {
				return nil, nil, fmt.Errorf("duplicate canonical serving target %s", target.ID)
			}
			targets[target.ID] = target
		case isTargetChannelStatePath(canonicalPath):
			body, err := readCanonicalLifecyclePath(canonical, canonicalPath)
			if err != nil {
				return nil, nil, err
			}
			channel, err := serving.DecodeChannel(body)
			if err != nil || channel.TargetID == "" || serving.ChannelStatePath(channel) != canonicalPath {
				return nil, nil, errors.Join(err, fmt.Errorf("canonical serving channel path %s does not match body", canonicalPath))
			}
			channels = append(channels, canonicalServingChannel{Path: canonicalPath, Channel: channel})
		}
	}
	for _, record := range channels {
		target, exists := targets[record.Channel.TargetID]
		if !exists || !targetMatchesChannel(target, record.Channel) {
			return nil, nil, fmt.Errorf("canonical channel %s has no matching target registry", record.Path)
		}
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].Path < channels[j].Path })
	return channels, targets, nil
}

func loadCanonicalServingLifecycle(canonical *state.Store) (canonicalServingLifecycle, error) {
	head, err := canonical.HeadHash()
	if err != nil {
		return canonicalServingLifecycle{}, err
	}
	return loadCanonicalServingLifecycleAt(canonical, head)
}

// loadCanonicalServingLifecycleAt reconstructs the complete immutable YUM
// serving topology at one reachable Git commit. Historical route receipts use
// this exact view so later channel rotations cannot retroactively redefine the
// mirrorlist or retained-generation bytes they admitted.
func loadCanonicalServingLifecycleAt(canonical *state.Store, commit plumbing.Hash) (canonicalServingLifecycle, error) {
	result := canonicalServingLifecycle{Targets: make(map[string]serving.TargetIdentity), Generations: make(map[string]canonicalServingGeneration), Retired: make(map[string]canonicalServingRetiredGeneration)}
	if canonical == nil {
		return result, errors.New("canonical serving lifecycle store is unavailable")
	}
	if commit.IsZero() {
		return result, nil
	}
	paths, err := canonical.ListFilesAt(commit, "serving/yum/")
	if err != nil {
		return result, err
	}
	pathSet := make(map[string]struct{}, len(paths))
	for _, canonicalPath := range paths {
		pathSet[canonicalPath] = struct{}{}
	}
	for _, canonicalPath := range paths {
		switch {
		case isTargetStatePath(canonicalPath):
			body, err := readCanonicalLifecyclePathAt(canonical, commit, canonicalPath)
			if err != nil {
				return result, err
			}
			target, err := decodeAnyServingTarget(body)
			if err != nil {
				return result, fmt.Errorf("decode canonical serving target %s: %w", canonicalPath, err)
			}
			if serving.TargetStatePath(target) != canonicalPath {
				return result, fmt.Errorf("canonical serving target path %s does not match body", canonicalPath)
			}
			if _, exists := result.Targets[target.ID]; exists {
				return result, fmt.Errorf("duplicate canonical serving target %s", target.ID)
			}
			result.Targets[target.ID] = target
		case isTargetChannelStatePath(canonicalPath):
			body, err := readCanonicalLifecyclePathAt(canonical, commit, canonicalPath)
			if err != nil {
				return result, err
			}
			channel, err := serving.DecodeChannel(body)
			if err != nil {
				return result, fmt.Errorf("decode canonical serving channel %s: %w", canonicalPath, err)
			}
			if serving.ChannelStatePath(channel) != canonicalPath || channel.TargetID == "" {
				return result, fmt.Errorf("canonical serving channel path %s does not match target-partitioned body", canonicalPath)
			}
			result.Channels = append(result.Channels, canonicalServingChannel{Path: canonicalPath, Channel: channel})
		case serving.IsGenerationManifestStatePath(canonicalPath):
			jsonPath := strings.TrimSuffix(canonicalPath, ".tsv") + ".json"
			if _, exists := pathSet[jsonPath]; !exists {
				return result, fmt.Errorf("canonical serving generation %s is missing JSON", canonicalPath)
			}
			generationBody, err := readCanonicalLifecyclePathAt(canonical, commit, jsonPath)
			if err != nil {
				return result, err
			}
			generation, err := serving.DecodeGeneration(generationBody)
			if err != nil {
				return result, fmt.Errorf("decode canonical serving generation %s: %w", jsonPath, err)
			}
			if serving.GenerationManifestStatePath(generation) != canonicalPath || serving.GenerationStatePath(generation) != jsonPath {
				return result, fmt.Errorf("canonical serving generation path %s does not match body", canonicalPath)
			}
			if err := validateCanonicalServingManifestAt(canonical, commit, canonicalPath, generation); err != nil {
				return result, err
			}
			coordinate := serving.GenerationCoordinate{ID: generation.ID, View: generation.View, Repo: generation.Repo, OS: generation.OS, Arch: generation.Arch}
			result.Generations[canonicalPath] = canonicalServingGeneration{Coordinate: coordinate, JSONPath: jsonPath, ManifestPath: canonicalPath, Generation: generation}
		case isGenerationJSONStatePath(canonicalPath):
			manifestPath := strings.TrimSuffix(canonicalPath, ".json") + ".tsv"
			if _, exists := pathSet[manifestPath]; !exists {
				return result, fmt.Errorf("canonical serving generation %s is missing manifest", canonicalPath)
			}
		case serving.IsRetiredGenerationStatePath(canonicalPath):
			manifestPath := strings.TrimSuffix(canonicalPath, ".json") + ".tsv"
			if _, exists := pathSet[manifestPath]; !exists {
				return result, fmt.Errorf("canonical retired generation %s is missing deletion witness", canonicalPath)
			}
			body, err := readCanonicalLifecyclePathAt(canonical, commit, canonicalPath)
			if err != nil {
				return result, err
			}
			retired, err := serving.DecodeRetiredGeneration(body)
			if err != nil || serving.RetiredGenerationStatePath(retired.Generation) != canonicalPath {
				return result, errors.Join(err, fmt.Errorf("canonical retired generation path %s does not match body", canonicalPath))
			}
			if serving.RetiredGenerationManifestStatePath(retired.Generation) != manifestPath {
				return result, fmt.Errorf("canonical retired deletion witness %s does not match body", manifestPath)
			}
			if err := validateCanonicalServingManifestAt(canonical, commit, manifestPath, retired.Generation); err != nil {
				return result, fmt.Errorf("validate retired generation deletion witness %s: %w", manifestPath, err)
			}
			result.Retired[canonicalPath] = canonicalServingRetiredGeneration{JSONPath: canonicalPath, ManifestPath: manifestPath, Retired: retired}
		case serving.IsRetiredGenerationManifestStatePath(canonicalPath):
			jsonPath := strings.TrimSuffix(canonicalPath, ".tsv") + ".json"
			if _, exists := pathSet[jsonPath]; !exists {
				return result, fmt.Errorf("canonical retired deletion witness %s is missing JSON", canonicalPath)
			}
		case strings.HasPrefix(canonicalPath, "serving/yum/channels/"):
			return result, fmt.Errorf("unpartitioned canonical serving channel requires migration: %s", canonicalPath)
		default:
			return result, fmt.Errorf("unknown canonical serving lifecycle path %s", canonicalPath)
		}
	}
	for manifestPath, generation := range result.Generations {
		retiredPath := serving.RetiredGenerationStatePath(generation.Generation)
		if _, exists := result.Retired[retiredPath]; exists {
			return result, fmt.Errorf("serving generation is both active and retired: %s", manifestPath)
		}
	}
	sort.Slice(result.Channels, func(i, j int) bool { return result.Channels[i].Path < result.Channels[j].Path })
	for _, record := range result.Channels {
		target, exists := result.Targets[record.Channel.TargetID]
		if !exists {
			return result, fmt.Errorf("canonical channel %s has no target registry", record.Path)
		}
		if target.Root != record.Channel.TargetRoot || target.BaseURL != record.Channel.BaseURL {
			return result, fmt.Errorf("canonical channel %s differs from target registry", record.Path)
		}
		pins, err := record.Channel.RetainedGenerationPins()
		if err != nil {
			return result, err
		}
		paths, err := serving.RetainedGenerationManifestPaths(record.Channel)
		if err != nil {
			return result, err
		}
		if len(pins) != len(paths) {
			return result, fmt.Errorf("canonical channel %s retained pin/path cardinality differs", record.Path)
		}
		for index, manifestPath := range paths {
			generation, exists := result.Generations[manifestPath]
			if !exists {
				return result, fmt.Errorf("canonical channel %s retains missing generation %s", record.Path, manifestPath)
			}
			actualPin, err := serving.PinGeneration(generation.Generation)
			if err != nil || actualPin != pins[index] {
				return result, errors.Join(err, fmt.Errorf("canonical channel %s retained pin differs from generation %s", record.Path, manifestPath))
			}
		}
	}
	return result, nil
}

func validateCanonicalServingManifest(canonical *state.Store, canonicalPath string, generation serving.Generation) error {
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return errors.Join(err, errors.New("canonical HEAD is unavailable for serving manifest validation"))
	}
	return validateCanonicalServingManifestAt(canonical, head, canonicalPath, generation)
}

func validateCanonicalServingManifestAt(canonical *state.Store, commit plumbing.Hash, canonicalPath string, generation serving.Generation) error {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	derived, deriveErr := serving.DeriveGeneration(serving.Identity{
		View: generation.View, Repo: generation.Repo, OS: generation.OS, Arch: generation.Arch,
		LegacyRoot: generation.LegacyRoot, RefCommit: generation.RefCommit,
		ConfigSHA256: generation.ConfigSHA256, RepositoryKeySHA256: generation.RepositoryKeySHA256,
	}, reader)
	closeErr := reader.Close()
	if deriveErr != nil || closeErr != nil {
		return fmt.Errorf("stream canonical serving generation manifest %s: %w", canonicalPath, errors.Join(deriveErr, closeErr))
	}
	if derived != generation {
		return fmt.Errorf("canonical serving generation manifest %s differs from JSON", canonicalPath)
	}
	return nil
}

func readCanonicalLifecyclePath(canonical *state.Store, canonicalPath string) ([]byte, error) {
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return nil, errors.Join(err, errors.New("canonical HEAD is unavailable for serving lifecycle read"))
	}
	return readCanonicalLifecyclePathAt(canonical, head, canonicalPath)
}

func readCanonicalLifecyclePathAt(canonical *state.Store, commit plumbing.Hash, canonicalPath string) ([]byte, error) {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, maxSecretBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(body) > maxSecretBytes {
		return nil, fmt.Errorf("canonical serving lifecycle path %s exceeds size limit", canonicalPath)
	}
	return body, nil
}

func isTargetStatePath(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 5 && parts[0] == "serving" && parts[1] == "yum" && parts[2] == "targets" && parts[3] != "" && parts[4] == "target.json"
}

func isTargetChannelStatePath(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 9 && parts[0] == "serving" && parts[1] == "yum" && parts[2] == "targets" && parts[3] != "" && parts[4] == "channels" && strings.HasSuffix(parts[8], ".json")
}

func isGenerationJSONStatePath(value string) bool {
	if !strings.HasSuffix(value, ".json") {
		return false
	}
	return serving.IsGenerationManifestStatePath(strings.TrimSuffix(value, ".json") + ".tsv")
}

func decodeAnyServingTarget(body []byte) (serving.TargetIdentity, error) {
	if target, err := serving.DecodeTargetIdentity("latest", body); err == nil {
		return target, nil
	}
	return serving.DecodeTargetIdentity("stable", body)
}

func journalServingGenerationPins(journals []localServingJournal) []serving.GenerationCoordinate {
	result := make([]serving.GenerationCoordinate, 0, len(journals)*2)
	for _, journal := range journals {
		result = append(result, serving.GenerationCoordinate{
			ID: journal.Generation.ID, View: journal.Generation.View, Repo: journal.Generation.Repo, OS: journal.Generation.OS, Arch: journal.Generation.Arch,
		})
		if journal.Channel.ParentGeneration != "" {
			result = append(result, serving.GenerationCoordinate{
				ID: journal.Channel.ParentGeneration, View: journal.Channel.View, Repo: journal.Channel.Repo, OS: journal.Channel.OS, Arch: journal.Channel.Arch,
			})
		}
	}
	return result
}

// retainedLocalServingManifestPaths exposes the exact existing canonical
// manifests that must be merged into a new leaf's Packages compatibility
// closure before deriving its generation ID.
func retainedLocalServingManifestPaths(canonical *state.Store, target serving.TargetIdentity, view, repo, osName, arch string) ([]string, error) {
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{})
	for _, record := range lifecycle.Channels {
		channel := record.Channel
		if channel.TargetID != target.ID || channel.View != view || channel.Repo != repo || channel.OS != osName || channel.Arch != arch {
			continue
		}
		paths, err := serving.RetainedGenerationManifestPaths(channel)
		if err != nil {
			return nil, err
		}
		for _, manifestPath := range paths {
			set[manifestPath] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for manifestPath := range set {
		result = append(result, manifestPath)
	}
	sort.Strings(result)
	return result, nil
}

func pruneCanonicalServingGenerationLedgers(ctx context.Context, canonical *state.Store, journals []localServingJournal) ([]canonicalServingGeneration, error) {
	return pruneCanonicalServingGenerationLedgersWithChannelDeletes(ctx, canonical, journals, nil)
}

// pruneCanonicalServingGenerationLedgersWithChannelDeletes atomically removes
// unavailable channels and retires every generation that those deletions
// unpin. This prevents a crash between channel deletion and retirement from
// stranding an active ledger after its target absence witness is removed.
func pruneCanonicalServingGenerationLedgersWithChannelDeletes(ctx context.Context, canonical *state.Store, journals []localServingJournal, channelDeletes []string) ([]canonicalServingGeneration, error) {
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		return nil, err
	}
	deleteSet := make(map[string]struct{}, len(channelDeletes))
	for _, canonicalPath := range channelDeletes {
		if !isTargetChannelStatePath(canonicalPath) {
			return nil, fmt.Errorf("invalid canonical serving channel deletion path %s", canonicalPath)
		}
		deleteSet[canonicalPath] = struct{}{}
	}
	channels := make([]serving.Channel, 0, len(lifecycle.Channels))
	for _, record := range lifecycle.Channels {
		if _, deleted := deleteSet[record.Path]; deleted {
			delete(deleteSet, record.Path)
			continue
		}
		channels = append(channels, record.Channel)
	}
	if len(deleteSet) != 0 {
		return nil, errors.New("canonical serving channel deletion path disappeared")
	}
	keep, err := serving.RetainedGenerationKeepSet(channels, journalServingGenerationPins(journals))
	if err != nil {
		return nil, err
	}
	var expired []canonicalServingGeneration
	deletePaths := append([]string(nil), channelDeletes...)
	staged := make(map[string]string)
	stageDir, err := os.MkdirTemp(canonical.StateDir(), "serving-retire-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stageDir)
	for manifestPath, record := range lifecycle.Generations {
		if _, retained := keep[manifestPath]; retained {
			continue
		}
		expired = append(expired, record)
		deletePaths = append(deletePaths, record.JSONPath, record.ManifestPath)
		retired, err := serving.NewRetiredGeneration(record.Generation)
		if err != nil {
			return nil, err
		}
		body, err := retired.Canonical()
		if err != nil {
			return nil, err
		}
		retiredPath := serving.RetiredGenerationStatePath(record.Generation)
		retiredManifestPath := serving.RetiredGenerationManifestStatePath(record.Generation)
		if existing, exists := lifecycle.Retired[retiredPath]; exists {
			existingBody, err := existing.Retired.Canonical()
			if err != nil || !bytes.Equal(existingBody, body) {
				return nil, errors.Join(err, errors.New("occupied retired generation identity differs"))
			}
		} else {
			stage := filepath.Join(stageDir, fmt.Sprintf("retired-%06d.json", len(staged)))
			if err := writeExclusiveBytes(stage, body); err != nil {
				return nil, err
			}
			staged[retiredPath] = stage
			manifestStage := filepath.Join(stageDir, fmt.Sprintf("retired-%06d.tsv", len(staged)))
			source, err := canonical.OpenPath(record.ManifestPath)
			if err != nil {
				return nil, err
			}
			copyErr := manifest.AtomicCopy(manifestStage, source, 0o600)
			closeErr := source.Close()
			if copyErr != nil || closeErr != nil {
				return nil, errors.Join(copyErr, closeErr)
			}
			staged[retiredManifestPath] = manifestStage
		}
	}
	if len(deletePaths) == 0 {
		return nil, nil
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i].ManifestPath < expired[j].ManifestPath })
	sort.Strings(deletePaths)
	if _, changed, err := applyCanonicalState(ctx, canonical, "serving-retention", "sow: prune expired local YUM generation ledgers and unavailable channels", staged, nil, state.ApplyOptions{DeletePaths: deletePaths}); err != nil {
		return nil, err
	} else if !changed {
		return nil, errors.New("serving retention selected ledgers but canonical transaction did not change")
	}
	return expired, nil
}

func targetMatchesChannel(target serving.TargetIdentity, channel serving.Channel) bool {
	return target.ID == channel.TargetID && target.Root == channel.TargetRoot && target.BaseURL == channel.BaseURL
}

// migrateLegacyServingChannels atomically partitions pre-target channel
// ledgers onto the default physical root while preserving their exact URL and
// pointer body. Occupied target/channel coordinates must be byte-identical.
func migrateLegacyServingChannels(ctx context.Context, cfg *config.Config, canonical *state.Store) (int, error) {
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return 0, err
	}
	paths, err := canonical.ListFilesAt(head, "serving/yum/channels/")
	if err != nil || len(paths) == 0 {
		return 0, err
	}
	stageDir, err := os.MkdirTemp(canonical.StateDir(), "serving-channel-migrate-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(stageDir)
	staged := make(map[string]string)
	deletePaths := make([]string, 0, len(paths))
	for index, canonicalPath := range paths {
		body, err := readCanonicalLifecyclePath(canonical, canonicalPath)
		if err != nil {
			return 0, err
		}
		channel, err := serving.DecodeChannel(body)
		if err != nil || channel.TargetID != "" || serving.ChannelStatePath(channel) != canonicalPath {
			return 0, errors.Join(err, fmt.Errorf("legacy serving channel path %s does not match body", canonicalPath))
		}
		targetRoot, err := defaultMutableServingTarget(cfg, channel.View)
		if err != nil {
			return 0, err
		}
		target, err := localServingTargetIdentity(cfg, channel.View, targetRoot, channel.BaseURL)
		if err != nil {
			return 0, err
		}
		channel.TargetID = target.ID
		channel.TargetRoot = target.Root
		channelBody, err := channel.Canonical()
		if err != nil {
			return 0, err
		}
		targetBody, err := target.Canonical(channel.View)
		if err != nil {
			return 0, err
		}
		for offset, item := range []struct {
			path string
			body []byte
		}{{serving.TargetStatePath(target), targetBody}, {serving.ChannelStatePath(channel), channelBody}} {
			if existing, exists, err := readOptionalCanonical(canonical, item.path); err != nil {
				return 0, err
			} else if exists {
				if !bytes.Equal(existing, item.body) {
					return 0, fmt.Errorf("legacy serving migration destination %s is occupied by different state", item.path)
				}
				continue
			}
			stage := filepath.Join(stageDir, fmt.Sprintf("migrate-%06d-%d.json", index, offset))
			if err := writeExclusiveBytes(stage, item.body); err != nil {
				return 0, err
			}
			staged[item.path] = stage
		}
		deletePaths = append(deletePaths, canonicalPath)
	}
	sort.Strings(deletePaths)
	if _, changed, err := applyCanonicalState(ctx, canonical, "serving-target-migration", "sow: partition legacy local YUM serving channels", staged, nil, state.ApplyOptions{DeletePaths: deletePaths}); err != nil {
		return 0, err
	} else if !changed {
		return 0, errors.New("legacy serving channels selected but migration did not change canonical state")
	}
	return len(deletePaths), nil
}
