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
	"sort"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

// localServingAuditEntry is one independently reportable part of the local
// strong-serving closure. Canonical lifecycle parsing and manifest staging
// happen before checks are scheduled; Run is read-only with respect to the
// repository and canonical state.
type localServingAuditEntry struct {
	ID      string
	Subject string
	Code    string
	Message string
	Run     func(context.Context) error
}

func buildLocalServingL1Checks(
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	repos []config.Repo,
	viewNames []string,
	values commonFlags,
	txDir string,
) ([]verify.Check, error) {
	entries, err := buildLocalServingAuditEntries(cfg, canonical, pool, repos, viewNames, values, txDir)
	if err != nil {
		return nil, err
	}
	checks := make([]verify.Check, 0, len(entries))
	for _, entry := range entries {
		entry := entry
		checks = append(checks, verify.CheckFunc{
			CheckID: entry.ID, CheckLayer: verify.LayerL1,
			Run: func(ctx context.Context, recorder *verify.Recorder) error {
				err := entry.Run(ctx)
				if err == nil {
					return nil
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				recorder.Add(verify.Finding{
					Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
					Code: entry.Code, Subject: entry.Subject, Message: entry.Message,
					Fields: []verify.Field{{Key: "reason", Value: err.Error()}},
				})
				return nil
			},
		})
	}
	return checks, nil
}

func buildLocalServingAuditEntries(
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	repos []config.Repo,
	viewNames []string,
	values commonFlags,
	txDir string,
) ([]localServingAuditEntry, error) {
	if cfg == nil || canonical == nil || pool == nil {
		return nil, errors.New("local serving audit requires configuration, canonical state, and CAS")
	}
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		return nil, fmt.Errorf("load canonical local YUM serving lifecycle: %w", err)
	}
	wantedViews := make(map[string]struct{}, len(viewNames))
	for _, view := range viewNames {
		wantedViews[view] = struct{}{}
	}
	wantedLeaves := make(map[string]localYUMServingLeaf)
	for _, leaf := range selectedLeaves(repos, values) {
		if leaf.repo.Type == "yum" {
			wantedLeaves[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = localYUMServingLeaf(leaf)
		}
	}
	fullSelection := localServingSelectionIsFull(values)
	compatibilityViews := append([]string(nil), viewNames...)
	if len(compatibilityViews) == 0 {
		// fsck audits every canonical channel and therefore has no explicit
		// view selector. Compatibility projections are deliberately defined
		// only for latest, so retain that owner-selection authority here.
		compatibilityViews = []string{"latest"}
	}
	selectedCompatibility, err := selectedLatestYUMCompatibilityForViews(cfg, repos, compatibilityViews, values)
	if err != nil {
		return nil, err
	}
	selectedCompatibilityByID := make(map[string]config.YUMCompatibilityProjection, len(selectedCompatibility))
	for _, projection := range selectedCompatibility {
		selectedCompatibilityByID[projection.ID] = projection
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return nil, err
	}
	canonicalHead, err := canonical.HeadHash()
	if err != nil {
		return nil, err
	}
	repositoryKeySHA := ""
	if len(lifecycle.Channels) != 0 {
		if cfg.GPG.PublicKey == "" {
			return nil, errors.New("canonical YUM serving state requires gpg.public_key")
		}
		_, packets, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey)
		if err != nil {
			return nil, err
		}
		repositoryKeySHA = repositoryTrustAnchorDigest(packets)
	}

	stagedManifests := make(map[string]string)
	var entries []localServingAuditEntry
	installWorkers := values.workers
	generationChecks := 0
	channelsByPath := make(map[string]canonicalServingChannel, len(lifecycle.Channels))
	channelCountByTarget := make(map[string]int, len(lifecycle.Targets))
	for _, record := range lifecycle.Channels {
		channelsByPath[record.Path] = record
		channelCountByTarget[record.Channel.TargetID]++
	}

	// A repository can legitimately be verified before its first materialize,
	// so absence alone is not a coverage failure. Once either the canonical
	// default-target registry or a physical mirrorlist exists, however, every
	// selected desired leaf must have exactly one target-partitioned channel.
	viewsForCoverage := append([]string(nil), viewNames...)
	if len(viewsForCoverage) == 0 {
		viewsForCoverage = []string{"beta", "latest", "stable"}
	}
	for _, view := range uniqueSorted(viewsForCoverage) {
		viewConfig, exists := cfg.Views[view]
		if !exists {
			continue
		}
		for _, leaf := range wantedLeaves {
			if !viewIncludesRepo(viewConfig, leaf.repo.ID) {
				continue
			}
			ref, err := state.ViewRef(view, leaf.repo.ID, leaf.os, leaf.arch)
			if err != nil {
				return nil, err
			}
			_, refExists, err := canonical.Ref(ref)
			if err != nil || !refExists {
				if err != nil {
					return nil, err
				}
				continue
			}
			targetRoot, err := defaultMutableServingTarget(cfg, view)
			if err != nil {
				return nil, err
			}
			mirrorlistPath := serving.MirrorlistPath(view, leaf.repo.ID, leaf.os, leaf.arch)
			_, pointerExists, pointerErr := serving.ReadMirrorlist(targetRoot, mirrorlistPath)
			if pointerErr != nil && !errors.Is(pointerErr, os.ErrNotExist) {
				subject := "physical:" + filepath.ToSlash(mirrorlistPath)
				entries = append(entries, localServingFailureEntry(subject, "pointer", "LOCAL_YUM_POINTER_DRIFT", "local YUM mirrorlist coordinate is unsafe", pointerErr.Error()))
				pointerExists = true
			}
			baseURL, baseErr := cfg.ServingBaseURL(view)
			if baseErr != nil {
				if pointerExists {
					entries = append(entries, localServingFailureEntry(ref.String(), "coverage", "LOCAL_YUM_CHANNEL_MISSING", "materialized local YUM leaf has no valid serving URL/channel", baseErr.Error()))
				}
				continue
			}
			targetIdentity, err := localServingTargetIdentity(cfg, view, targetRoot, baseURL)
			if err != nil {
				return nil, err
			}
			channelPath := serving.ChannelStatePath(serving.Channel{TargetID: targetIdentity.ID, View: view, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch})
			_, targetExists := lifecycle.Targets[targetIdentity.ID]
			if !targetExists && !pointerExists {
				continue
			}
			if _, channelExists := channelsByPath[channelPath]; !channelExists {
				reason := "default target or mirrorlist exists without the selected desired channel"
				entries = append(entries, localServingFailureEntry(channelPath, "coverage", "LOCAL_YUM_CHANNEL_MISSING", "selected local YUM serving leaf has no canonical channel", reason))
			}
		}
	}
	// S3 is explicit authority to expose the frozen compatibility generation.
	// Unlike an ordinary repository that may validly exist before its first
	// materialization, an active S3 ledger without the exact default-target
	// channel is an incomplete cutover and must never be reported clean.
	for _, projection := range selectedCompatibility {
		active, err := publicationYUMCompatibilityActiveAt(canonical, canonicalHead, projection.ID)
		if err != nil {
			return nil, fmt.Errorf("read compatibility cutover authority %s: %w", projection.ID, err)
		}
		if !active {
			continue
		}
		targetRoot, err := defaultMutableServingTarget(cfg, "latest")
		if err != nil {
			return nil, err
		}
		baseURL, err := cfg.ServingBaseURL("latest")
		if err != nil {
			return nil, err
		}
		targetIdentity, err := localServingTargetIdentity(cfg, "latest", targetRoot, baseURL)
		if err != nil {
			return nil, err
		}
		channelPath := serving.ChannelStatePath(serving.Channel{
			TargetID: targetIdentity.ID, View: "latest", Repo: projection.ID,
			OS: "cross-el", Arch: projection.Source.Arch,
		})
		if _, exists := channelsByPath[channelPath]; !exists {
			entries = append(entries, localServingFailureEntry(
				channelPath, "coverage", "LOCAL_YUM_CHANNEL_MISSING",
				"active S3 compatibility projection has no canonical local serving channel",
				"cutover authority exists without the exact default-target generation/channel transaction",
			))
		}
	}

	for _, record := range lifecycle.Channels {
		channel := record.Channel
		if len(wantedViews) != 0 {
			if _, wanted := wantedViews[channel.View]; !wanted {
				continue
			}
		}
		leaf, leafSelected := wantedLeaves[servingLeafKey(channel.Repo, channel.OS, channel.Arch)]
		projection, compatibilityChannel, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, channel.Repo)
		if err != nil {
			return nil, err
		}
		_, compatibilitySelected := selectedCompatibilityByID[channel.Repo]
		if !leafSelected && !compatibilitySelected && !fullSelection {
			continue
		}
		topologyReason := ""
		viewConfig, viewExists := cfg.Views[channel.View]
		var expectedRefCommit, expectedLegacyRoot, expectedRepositoryKeySHA string
		var compatibilityEvidence frozenYUMCompatibilityServingEvidence
		if compatibilityChannel {
			switch {
			case !compatibilitySelected:
				topologyReason = "canonical compatibility channel is outside the configured selected owner topology"
			case channel.View != projection.Source.View || channel.View != "latest" || channel.OS != "cross-el" || channel.Arch != projection.Source.Arch:
				topologyReason = "canonical compatibility channel has non-canonical view, OS, or architecture coordinates"
			case !viewExists || !viewIncludesRepo(viewConfig, projection.Source.Repo):
				topologyReason = "canonical compatibility channel owner is excluded from its configured view"
			default:
				active, activeErr := publicationYUMCompatibilityActiveAt(canonical, canonicalHead, projection.ID)
				if activeErr != nil {
					return nil, fmt.Errorf("read compatibility cutover authority %s: %w", projection.ID, activeErr)
				}
				if !active {
					topologyReason = "canonical compatibility channel remains after S3 authority was absent or rolled back"
					break
				}
				compatibilityEvidence, err = loadFrozenYUMCompatibilityServingEvidence(cfg, canonical, projection)
				if err != nil {
					return nil, fmt.Errorf("load frozen compatibility serving evidence %s: %w", projection.ID, err)
				}
				expectedRefCommit = compatibilityEvidence.freezeCommit.String()
				expectedLegacyRoot = projection.Root
				expectedRepositoryKeySHA = compatibilityEvidence.receipt.RepositoryKeySHA256
			}
		} else if !leafSelected {
			topologyReason = "canonical serving channel is outside the configured YUM topology"
		} else if !viewExists || !viewIncludesRepo(viewConfig, channel.Repo) {
			topologyReason = "canonical serving channel is excluded from its configured view"
		} else {
			ref, err := state.ViewRef(channel.View, channel.Repo, channel.OS, channel.Arch)
			if err != nil {
				return nil, err
			}
			commit, refExists, err := canonical.Ref(ref)
			if err != nil {
				return nil, err
			}
			if !refExists {
				topologyReason = "canonical serving channel has no desired view ref"
			} else {
				expectedRefCommit = commit.String()
				expectedLegacyRoot, err = leaf.repo.PathForArch(leaf.arch)
				if err != nil {
					return nil, err
				}
				expectedRepositoryKeySHA = repositoryKeySHA
			}
		}
		if topologyReason != "" {
			reason := topologyReason
			entries = append(entries, localServingAuditEntry{
				ID:      localServingAuditID(record.Path, "topology"),
				Subject: record.Path,
				Code:    "LOCAL_YUM_TOPOLOGY_DRIFT",
				Message: "canonical local YUM serving topology contains an obsolete channel",
				Run: func(context.Context) error {
					return errors.New(reason)
				},
			})
			continue
		}
		if channel.RefCommit != expectedRefCommit || channel.ConfigSHA256 != configSHA || channel.RepositoryKeySHA256 != expectedRepositoryKeySHA || channel.LegacyRoot != expectedLegacyRoot {
			reason := "channel identity differs from current view ref, configuration, trust anchor, or repository root"
			entries = append(entries, localServingFailureEntry(record.Path, "desired", "LOCAL_YUM_DESIRED_DRIFT", "canonical local YUM channel is stale relative to current desired state", reason))
		}
		target, exists := lifecycle.Targets[channel.TargetID]
		if !exists {
			return nil, fmt.Errorf("canonical serving channel %s has no target registry", record.Path)
		}
		targetRoot := cfg.Root
		if target.Root != "." {
			targetRoot = filepath.Join(cfg.Root, filepath.FromSlash(target.Root))
		}
		channelCopy := channel
		pointerSubject := record.Path
		entries = append(entries, localServingAuditEntry{
			ID:      localServingAuditID(pointerSubject, "pointer"),
			Subject: pointerSubject,
			Code:    "LOCAL_YUM_POINTER_DRIFT",
			Message: "local YUM mirrorlist is absent, unsafe, or differs from canonical channel state",
			Run: func(ctx context.Context) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				wanted, err := channelCopy.MirrorlistBody()
				if err != nil {
					return err
				}
				observed, exists, err := serving.ReadMirrorlist(targetRoot, channelCopy.MirrorlistPath)
				if err != nil {
					return err
				}
				if !exists {
					return errors.New("canonical mirrorlist is missing")
				}
				if !bytes.Equal(observed, wanted) {
					return errors.New("mirrorlist bytes differ from canonical channel")
				}
				return serving.ValidateMirrorlistPermissions(targetRoot, channelCopy.MirrorlistPath)
			},
		})
		if compatibilityChannel {
			evidenceCopy := compatibilityEvidence
			trustSubject := record.Path + "#trust"
			entries = append(entries, localServingAuditEntry{
				ID:      localServingAuditID(trustSubject, "trust"),
				Subject: trustSubject,
				Code:    "LOCAL_YUM_COMPATIBILITY_TRUST_DRIFT",
				Message: "active compatibility trust routes are absent, drifted, or not exact CAS hardlinks",
				Run: func(ctx context.Context) error {
					return validateInstalledFrozenYUMCompatibilityTrust(ctx, pool, targetRoot, evidenceCopy)
				},
			})
		}

		pins, err := channel.RetainedGenerationPins()
		if err != nil {
			return nil, err
		}
		coordinates, err := channel.RetainedGenerationCoordinates()
		if err != nil || len(coordinates) != len(pins) {
			return nil, errors.Join(err, errors.New("canonical channel retained-generation coordinates are inconsistent"))
		}
		for index, coordinate := range coordinates {
			manifestStatePath, err := coordinate.ManifestPath()
			if err != nil {
				return nil, err
			}
			generationRecord, exists := lifecycle.Generations[manifestStatePath]
			if !exists {
				return nil, fmt.Errorf("canonical channel %s retains missing generation %s", record.Path, manifestStatePath)
			}
			pin := pins[index]
			generation := generationRecord.Generation
			if generation.ID != pin.ID || generation.ContentSHA256 != pin.ContentSHA256 || generation.ManifestSHA256 != pin.ManifestSHA256 {
				return nil, fmt.Errorf("canonical channel %s retained pin differs from generation %s", record.Path, manifestStatePath)
			}
			stagedManifest, exists := stagedManifests[manifestStatePath]
			if !exists {
				stagedManifest, err = stageCanonicalServingAuditManifest(canonical, manifestStatePath, txDir)
				if err != nil {
					return nil, err
				}
				stagedManifests[manifestStatePath] = stagedManifest
			}
			scratch, err := os.MkdirTemp(txDir, "serving-audit-")
			if err != nil {
				return nil, err
			}
			generationCopy, manifestCopy := generation, stagedManifest
			generationSubject := record.Path + "#generation=" + generation.ID
			generationChecks++
			entries = append(entries, localServingAuditEntry{
				ID:      localServingAuditID(generationSubject, "generation"),
				Subject: generationSubject,
				Code:    "LOCAL_YUM_GENERATION_DRIFT",
				Message: "retained local YUM generation is absent, drifted, non-hostable, or not hardlinked to canonical CAS",
				Run: func(ctx context.Context) error {
					return serving.ValidateInstalledGeneration(ctx, pool, targetRoot, generationCopy, manifestCopy, serving.InstallOptions{
						Workers: installWorkers, ChunkEntries: values.chunk, TempDir: scratch,
					})
				},
			})
		}
	}
	if fullSelection {
		for targetID, target := range lifecycle.Targets {
			if channelCountByTarget[targetID] == 0 {
				subject := serving.TargetStatePath(target)
				entries = append(entries, localServingFailureEntry(subject, "topology", "LOCAL_YUM_TOPOLOGY_DRIFT", "canonical local YUM target registry has no channels", "dangling serving target registry"))
			}
		}
	}
	// verify.Run already schedules independent checks with values.workers. Split
	// that fixed budget across retained-generation inner scanners so current +
	// Previous validation cannot multiply into workers squared at 50k scale.
	if generationChecks != 0 {
		outerWorkers := min(values.workers, generationChecks)
		installWorkers = max(1, values.workers/outerWorkers)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

func stageCanonicalServingAuditManifest(canonical *state.Store, canonicalPath, txDir string) (string, error) {
	digest := sha256.Sum256([]byte(canonicalPath))
	destination := filepath.Join(txDir, "serving-manifest-"+hex.EncodeToString(digest[:])+".tsv")
	reader, err := canonical.OpenPath(canonicalPath)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = reader.Close()
		return "", err
	}
	limited := &io.LimitedReader{R: reader, N: localServingCanonicalManifestMaxBytes + 1}
	_, copyErr := io.Copy(file, limited)
	closeErr := errors.Join(reader.Close(), file.Sync(), file.Close())
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(destination)
		return "", errors.Join(copyErr, closeErr)
	}
	if limited.N == 0 {
		_ = os.Remove(destination)
		return "", fmt.Errorf("canonical serving audit manifest exceeds %d-byte safety limit", localServingCanonicalManifestMaxBytes)
	}
	return destination, nil
}

func localServingAuditID(subject, kind string) string {
	digest := sha256.Sum256([]byte(subject))
	return "serving/yum/" + hex.EncodeToString(digest[:]) + "/" + kind
}

func localServingFailureEntry(subject, kind, code, message, reason string) localServingAuditEntry {
	return localServingAuditEntry{
		ID: localServingAuditID(subject, kind), Subject: subject, Code: code, Message: message,
		Run: func(context.Context) error { return errors.New(reason) },
	}
}
