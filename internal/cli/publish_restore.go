package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type restoreAuditSource struct {
	Generation uint64
	SHA256     string
	PlanSHA256 string
	Commit     string
	Refs       []pub.RefState
}

const restoreAuditSchema = "sow-restore/v1"

type restoreAuditRecord struct {
	Schema                 string         `json:"schema"`
	Target                 string         `json:"target"`
	Generation             uint64         `json:"generation"`
	SourceGeneration       uint64         `json:"source_generation"`
	SourceGenerationSHA256 string         `json:"source_generation_sha256"`
	SourcePlanSHA256       string         `json:"source_plan_sha256"`
	SourceStateCommit      string         `json:"source_state_commit"`
	IntentView             string         `json:"intent_view"`
	IntentSnapshot         string         `json:"intent_snapshot,omitempty"`
	TransactionID          string         `json:"transaction_id"`
	Refs                   []pub.RefState `json:"refs"`
}

type historicalTargetPublication struct {
	StateCommit plumbing.Hash
	Generation  pub.TargetGeneration
	SHA256      string
	PlanSHA256  string
}

func historicalRestoreMaterializationPaths(cfg *config.Config, target string, generation pub.TargetGeneration) (string, string) {
	restoreLabel := generation.IntentView
	if generation.IntentSnapshot != "" {
		restoreLabel = generation.IntentSnapshot
	}
	relative := filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "restores", target, fmt.Sprintf("%020d", generation.Generation), restoreLabel))
	return relative, filepath.Join(cfg.Root, filepath.FromSlash(relative))
}

func restoreRefStateSlice(values map[string]pub.RefState) []pub.RefState {
	result := make([]pub.RefState, 0, len(values))
	for _, ref := range values {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func publicationRefMatchesIntent(name, view, snapshot string) bool {
	if view == "snapshot" {
		return strings.HasPrefix(name, "refs/sow/snapshots/"+snapshot+"/")
	}
	return strings.HasPrefix(name, "refs/sow/views/"+view+"/")
}

func restoreSourceGenerationFromTransactionID(transactionID string) (uint64, bool) {
	const marker = "-from-"
	index := strings.LastIndex(transactionID, marker)
	if index < 0 {
		return 0, false
	}
	remainder := transactionID[index+len(marker):]
	if len(remainder) < 21 || remainder[20] != '-' {
		return 0, false
	}
	generation, err := strconv.ParseUint(remainder[:20], 10, 64)
	return generation, err == nil && generation != 0
}

func publicationDesiredCommitFromTransactionID(transactionID string) (plumbing.Hash, bool) {
	const marker = "-head-"
	index := strings.LastIndex(transactionID, marker)
	if index < 0 {
		return plumbing.ZeroHash, false
	}
	remainder := transactionID[index+len(marker):]
	if len(remainder) < 41 || remainder[40] != '-' {
		return plumbing.ZeroHash, false
	}
	decoded, err := hex.DecodeString(remainder[:40])
	if err != nil || len(decoded) != 20 {
		return plumbing.ZeroHash, false
	}
	commit := plumbing.NewHash(remainder[:40])
	return commit, !commit.IsZero()
}

// localizeIsolatedPublicationSources rewrites logical manifest paths only for
// projections prepared in a non-hosted localRoot. Ordinary projections retain
// their source paths. Historical restore requires every classified projection
// to be isolated; ordinary publish uses the same mechanism only for frozen
// compatibility candidates.
func localizeIsolatedPublicationSources(plan *pub.Plan, classifier publicationClassifier, requireAll bool) error {
	if plan == nil {
		return errors.New("nil publication plan")
	}
	for index := range plan.Objects {
		object := &plan.Objects[index]
		projection, relative, err := classifier.projection(object.SourcePath)
		if err == nil {
			if projection.localRoot == "" {
				if requireAll {
					return fmt.Errorf("historical publication source %s has no isolated local root", object.SourcePath)
				}
				continue
			}
			object.SourcePath = path.Join(projection.localRoot, relative)
			continue
		}
		if strings.HasPrefix(object.SourcePath, ".sow/generated/") {
			continue
		}
		if requireAll {
			return fmt.Errorf("historical publication source %s cannot be localized: %w", object.SourcePath, err)
		}
	}
	return nil
}

func restorePublishedGeneration(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, target string, generation uint64, txDir string, values commonFlags, privateKeyFile, passphraseFile string, stdout io.Writer) error {
	historical, err := loadHistoricalTargetPublication(canonical, target, generation)
	if err != nil {
		return withExitCode(ExitConflict, "load historical target generation: %v", err)
	}
	configSHA, err := publicationConfigSHA256ForGeneration(cfg, historical.Generation)
	if err != nil {
		return withExitCode(ExitConfig, "hash current configuration: %v", err)
	}
	if configSHA != historical.Generation.ConfigSHA256 {
		return withExitCode(ExitConflict, "historical target generation %d config_sha256=%s differs from current %s", generation, historical.Generation.ConfigSHA256, configSHA)
	}
	historicalLeaves, err := configuredHistoricalLeaves(cfg, historical.Generation)
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	leaves := make([]viewLeaf, 0, len(historicalLeaves))
	for _, historicalLeaf := range historicalLeaves {
		leaves = append(leaves, historicalLeaf.leaf)
	}
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, privateKeyFile, passphraseFile)
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	values.materializeTrust, err = captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		return withExitCode(ExitConflict, "capture restore materialization trust: %v", err)
	}
	values.materializeOperation = "publish"

	// A durable historical selected set is local recovery authority. Complete
	// its exact CAS/ref projection before even the read-only remote observation
	// below, so a network outage cannot block local convergence and no provider
	// request can cross an active local mutation fence. The historical
	// generation itself is a sufficient synthetic parent for this recovery-only
	// preparation: topology comparison against the real current parent is still
	// performed after remote observation, before any remote mutation.
	journal, activeMaterialization, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil {
		return withExitCode(ExitConflict, "inspect historical materialization recovery: %v", err)
	}
	if activeMaterialization {
		if !values.recover {
			return withExitCode(ExitConflict, "historical materialization recovery requires --recover")
		}
		recovery, err := decodePublicationMaterializationRecovery(cfg, journal)
		if err != nil || recovery.kind != publicationMaterializationRecoveryRestore {
			return withExitCode(ExitConflict, "historical restore cannot adopt a different materialization intent: %v", errors.Join(err, fmt.Errorf("durable kind=%s", recovery.kind)))
		}
		recoveryDir := filepath.Join(txDir, "restore-local-recovery")
		if err := os.Mkdir(recoveryDir, 0o700); err != nil {
			return withExitCode(ExitInternal, "create historical local recovery transaction: %v", err)
		}
		syntheticParent := historical.Generation
		recovered, err := prepareHistoricalPublication(ctx, cfg, cfg, canonical, pool, repos, target, historical, &syntheticParent, recoveryDir, values, privateKey, passphrase, stdout)
		if recovered.restoreRoot != "" {
			defer os.RemoveAll(recovered.restoreRoot)
		}
		if err != nil {
			return err
		}
		if _, stillActive, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || stillActive {
			return withExitCode(ExitConflict, "historical local materialization recovery did not clear its durable fence: %v", err)
		}
		fmt.Fprintf(stdout, "recovered historical local materialization target=%s source_generation=%d intent=%s\n", target, generation, recovered.label())
	}

	client, err := newPublishTargetClient(cfg, target, historical.Generation.IntentView, historical.Generation.IntentView == "snapshot" || cfg.Views[historical.Generation.IntentView].Access == "pro")
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	inspectionDir := filepath.Join(txDir, "restore-inspection")
	if err := os.Mkdir(inspectionDir, 0o700); err != nil {
		return withExitCode(ExitInternal, "create restore inspection: %v", err)
	}
	observation, err := observeRemoteTarget(ctx, canonical, client, target, inspectionDir)
	if err != nil {
		return publishTargetExitError(err)
	}
	if observation.parent == nil {
		return withExitCode(ExitConflict, "target %s has no committed local/remote generation to restore", target)
	}
	parentStateCommit, parentState, err := targetGenerationPublicationState(canonical, target, observation.parent.Generation)
	if err != nil {
		return withExitCode(ExitConflict, "locate current parent publication state: %v", err)
	}
	parentBody, _ := observation.parent.Canonical()
	committedParentBody, _ := parentState.Canonical()
	if !bytes.Equal(parentBody, committedParentBody) {
		return withExitCode(ExitConflict, "current parent generation differs from its canonical publication state")
	}
	parentCfg, err := canonicalConfigurationAt(canonical, parentStateCommit, cfg)
	if err != nil {
		return withExitCode(ExitConflict, "load current parent configuration: %v", err)
	}
	parentConfigSHA, err := publicationConfigSHA256ForGeneration(parentCfg, *observation.parent)
	if err != nil || parentConfigSHA != observation.parent.ConfigSHA256 {
		return withExitCode(ExitConflict, "current parent canonical configuration digest=%s want=%s: %v", parentConfigSHA, observation.parent.ConfigSHA256, err)
	}
	if err := validatePublishedRepositoryKeyContinuity(parentCfg, target, *observation.parent, repositoryKeySHA); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if generation >= observation.parent.Generation {
		return withExitCode(ExitUsage, "--restore-generation %d must be older than target %s current generation %d", generation, target, observation.parent.Generation)
	}
	if observation.resumeGeneration != nil && !pub.SamePublicationIntent(observation.resumeGeneration.IntentView, observation.resumeGeneration.IntentSnapshot, historical.Generation.IntentView, historical.Generation.IntentSnapshot) {
		return withExitCode(ExitConflict, "target %s has an interrupted %s/%s publication; recover it before restoring %s/%s", target, observation.resumeGeneration.IntentView, observation.resumeGeneration.IntentSnapshot, historical.Generation.IntentView, historical.Generation.IntentSnapshot)
	}
	if observation.resumeCheckpoint != nil && !pub.SamePublicationIntent(observation.resumeCheckpoint.IntentView, observation.resumeCheckpoint.IntentSnapshot, historical.Generation.IntentView, historical.Generation.IntentSnapshot) {
		return withExitCode(ExitConflict, "target %s has an interrupted %s/%s checkpoint; recover it before restoring %s/%s", target, observation.resumeCheckpoint.IntentView, observation.resumeCheckpoint.IntentSnapshot, historical.Generation.IntentView, historical.Generation.IntentSnapshot)
	}
	if observation.resumeLock != nil && !pub.SamePublicationIntent(observation.resumeLock.IntentView, observation.resumeLock.IntentSnapshot, historical.Generation.IntentView, historical.Generation.IntentSnapshot) {
		return withExitCode(ExitConflict, "target %s has an interrupted %s/%s lock; recover it before restoring %s/%s", target, observation.resumeLock.IntentView, observation.resumeLock.IntentSnapshot, historical.Generation.IntentView, historical.Generation.IntentSnapshot)
	}
	if observation.resumeGeneration == nil && observation.resumeCheckpoint == nil && observation.resumeLock == nil {
		if err := validateHistoricalGenerationCompatibility(cfg, canonical, target, historical.Generation, historical.StateCommit); err != nil {
			return withExitCode(ExitVerification, "validate historical compatibility vector: %v", err)
		}
		unchanged, err := currentGenerationRestoresHistoricalSource(canonical, target, observation.parent.Generation, historical)
		if err != nil {
			return withExitCode(ExitVerification, "%v", err)
		}
		if unchanged {
			selection := "view=" + historical.Generation.IntentView
			if historical.Generation.IntentSnapshot != "" {
				selection += " snapshot=" + historical.Generation.IntentSnapshot
			}
			fmt.Fprintf(stdout, "publish target=%s %s status=unchanged\n", target, selection)
			fmt.Fprintf(stdout, "restore target=%s source_generation=%d intent=%s source_state_commit=%s status=complete\n", target, generation, historical.Generation.IntentView, historical.StateCommit)
			return nil
		}
	}

	prepared, err := prepareHistoricalPublication(ctx, cfg, parentCfg, canonical, pool, repos, target, historical, observation.parent, txDir, values, privateKey, passphrase, stdout)
	if prepared.restoreRoot != "" {
		defer os.RemoveAll(prepared.restoreRoot)
	}
	if err != nil {
		return err
	}
	prepared.repositoryKeySHA256 = repositoryKeySHA
	desiredCommit, err := canonical.HeadHash()
	if err != nil || desiredCommit.IsZero() {
		return withExitCode(ExitConflict, "restore requires initialized canonical state: %v", err)
	}
	failures, err := publishPreparedView(ctx, cfg, canonical, repos, prepared, []string{target}, desiredCommit, txDir, values, stdout)
	if err != nil {
		return err
	}
	if len(failures) != 0 {
		return withExitCode(ExitPartialPublish, "restore target %s remains behind", target)
	}
	fmt.Fprintf(stdout, "restore target=%s source_generation=%d intent=%s source_state_commit=%s status=complete\n", target, generation, prepared.label(), historical.StateCommit)
	return nil
}

func loadHistoricalTargetPublication(canonical *state.Store, target string, generation uint64) (historicalTargetPublication, error) {
	var result historicalTargetPublication
	if generation == 0 {
		return result, errors.New("historical generation must be positive")
	}
	history, err := canonical.History()
	if err != nil {
		return result, err
	}
	historySet := make(map[plumbing.Hash]struct{}, len(history))
	for _, commit := range history {
		historySet[commit] = struct{}{}
	}
	generationPath := remoteStatePath(target, "generation.json")
	for _, commit := range history {
		body, exists, err := readCanonicalBytesAt(canonical, commit, generationPath, 16<<20)
		if err != nil {
			return result, err
		}
		if !exists {
			continue
		}
		candidate, err := pub.DecodeTargetGeneration(body)
		if err != nil {
			return result, fmt.Errorf("decode canonical target generation at %s: %w", commit, err)
		}
		if string(candidate.Target) != target || candidate.Generation != generation {
			continue
		}
		closure, closureExists, err := loadHistoricalPublicationClosureAt(canonical, target, commit)
		if err != nil || !closureExists {
			return result, errors.Join(err, errors.New("historical target publication closure is missing"))
		}
		candidate = closure.generation
		desiredCommit := plumbing.NewHash(candidate.DesiredCommit)
		if _, exists := historySet[desiredCommit]; !exists {
			return result, fmt.Errorf("historical desired commit %s is outside canonical HEAD history", desiredCommit)
		}
		return historicalTargetPublication{
			StateCommit: commit, Generation: candidate, SHA256: digestBytesCLI(closure.generationBody),
			PlanSHA256: digestBytesCLI(closure.planBody),
		}, nil
	}
	return result, fmt.Errorf("target %s generation %d is not present in canonical successful-publication history", target, generation)
}

// targetGenerationPublicationState returns the first canonical commit that
// persisted one target generation. Later commits may retain the same generation
// while another target advances, so using the aggregate HEAD or DesiredCommit
// would not identify the configuration and plan that actually published it.
func targetGenerationPublicationState(canonical *state.Store, target string, generation uint64) (plumbing.Hash, pub.TargetGeneration, error) {
	var resultCommit plumbing.Hash
	var result pub.TargetGeneration
	if canonical == nil || generation == 0 {
		return resultCommit, result, errors.New("target generation publication state requires canonical state and a positive generation")
	}
	history, err := canonical.History()
	if err != nil {
		return resultCommit, result, err
	}
	statePath := remoteStatePath(target, "generation.json")
	var canonicalBody []byte
	// History is newest first. Overwrite result for every identical occurrence so
	// the final value is the oldest commit that already contains this generation.
	for _, commit := range history {
		body, exists, err := readCanonicalBytesAt(canonical, commit, statePath, 16<<20)
		if err != nil {
			return resultCommit, result, err
		}
		if !exists {
			continue
		}
		candidate, err := pub.DecodeTargetGeneration(body)
		if err != nil {
			return resultCommit, result, fmt.Errorf("decode target generation at %s: %w", commit, err)
		}
		if string(candidate.Target) != target || candidate.Generation != generation {
			continue
		}
		if canonicalBody != nil && !bytes.Equal(canonicalBody, body) {
			return resultCommit, result, fmt.Errorf("%w: target %s generation %d has multiple canonical encodings", pub.ErrDrift, target, generation)
		}
		canonicalBody = append(canonicalBody[:0], body...)
		resultCommit, result = commit, candidate
	}
	if resultCommit.IsZero() {
		return resultCommit, result, fmt.Errorf("target %s generation %d has no canonical publication state", target, generation)
	}
	return resultCommit, result, nil
}

func readCanonicalBytesAt(canonical *state.Store, commit plumbing.Hash, name string, maximum int64) ([]byte, bool, error) {
	reader, err := canonical.OpenPathAt(commit, name)
	if errors.Is(err, object.ErrFileNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, maximum+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, false, errors.Join(readErr, closeErr)
	}
	if int64(len(body)) > maximum {
		return nil, false, fmt.Errorf("canonical state %s exceeds %d bytes", name, maximum)
	}
	return body, true, nil
}

func readCanonicalConfigBytesAt(canonical *state.Store, commit plumbing.Hash) ([]byte, bool, error) {
	return readCanonicalBytesAt(canonical, commit, "config/sow.yaml", config.MaxConfigBytes)
}

func hashCanonicalPathOptionalAt(canonical *state.Store, commit plumbing.Hash, name string) (string, bool, error) {
	reader, err := canonical.OpenPathAt(commit, name)
	if errors.Is(err, object.ErrFileNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return "", false, errors.Join(copyErr, closeErr)
	}
	return hex.EncodeToString(hasher.Sum(nil)), true, nil
}

func prepareHistoricalPublication(ctx context.Context, cfg, parentCfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, target string, historical historicalTargetPublication, parent *pub.TargetGeneration, txDir string, values commonFlags, privateKey, passphrase []byte, stdout io.Writer) (prepared preparedPublication, resultErr error) {
	generation := historical.Generation
	if parent == nil {
		return prepared, withExitCode(ExitConflict, "historical restore requires a committed current parent generation")
	}
	if err := validateHistoricalGenerationCompatibility(cfg, canonical, target, generation, historical.StateCommit); err != nil {
		return prepared, withExitCode(ExitVerification, "validate historical compatibility vector: %v", err)
	}
	prepared = preparedPublication{
		view: generation.IntentView, snapshotID: generation.IntentSnapshot,
		refOverrides:                  make(map[string]pub.RefState),
		restoreRemovedProjectionRoots: make(map[string]bool),
		restoreRemovedChannelKeys:     make(map[string]bool),
		restoreSourceGeneration:       generation.Generation, restoreSourceSHA256: historical.SHA256,
		restoreSourcePlanSHA256: historical.PlanSHA256, restoreSourceCommit: historical.StateCommit.String(),
		restoreParentContentSHA256: parent.ContentManifestSHA256,
	}
	prepared.restoreCompatibility = append([]pub.CompatibilityState(nil), generation.Compatibility...)
	for _, channel := range generation.Channels {
		if channel.OS == "cross-el" {
			prepared.restoreCompatibilityChannels = append(prepared.restoreCompatibilityChannels, channel)
		}
	}
	sort.Slice(prepared.restoreCompatibility, func(i, j int) bool { return prepared.restoreCompatibility[i].ID < prepared.restoreCompatibility[j].ID })
	sort.Slice(prepared.restoreCompatibilityChannels, func(i, j int) bool {
		return prepared.restoreCompatibilityChannels[i].RemoteKey < prepared.restoreCompatibilityChannels[j].RemoteKey
	})
	compatibilityRestores, err := stageHistoricalCompatibilityRestores(canonical, cfg, historical.StateCommit, generation, txDir)
	if err != nil {
		return prepared, withExitCode(ExitVerification, "stage historical compatibility candidates: %v", err)
	}
	leavesByRef, err := configuredHistoricalLeaves(cfg, generation)
	if err != nil {
		return prepared, withExitCode(ExitConfig, "%v", err)
	}
	if prepared.view == "stable" {
		parentStable := make(map[string]pub.RefState)
		for _, ref := range parent.Refs {
			if publicationRefMatchesIntent(ref.Name, prepared.view, prepared.snapshotID) {
				parentStable[ref.Name] = ref
			}
		}
		if len(parentStable) != len(leavesByRef) {
			return prepared, withExitCode(ExitConflict, "stable restore generation %d would change the append-only stable ref vector; stable rollback is fail-closed", generation.Generation)
		}
		for name, historicalLeaf := range leavesByRef {
			if current, exists := parentStable[name]; !exists || current != historicalLeaf.ref {
				return prepared, withExitCode(ExitConflict, "stable restore generation %d would change append-only ref %s; stable rollback is fail-closed", generation.Generation, name)
			}
		}
	}
	if parentCfg == nil {
		return prepared, withExitCode(ExitConflict, "current parent canonical configuration is unavailable")
	}
	configuredByRef, err := configuredPublicationLeaves(parentCfg, prepared.view, prepared.snapshotID)
	if err != nil {
		return prepared, withExitCode(ExitConflict, "load current parent topology: %v", err)
	}
	var removedTopologyLeaves []viewLeaf
	for _, ref := range parent.Refs {
		if publicationRefMatchesIntent(ref.Name, prepared.view, prepared.snapshotID) {
			if _, exists := leavesByRef[ref.Name]; !exists {
				leaf, configured := configuredByRef[ref.Name]
				if !configured {
					return prepared, withExitCode(ExitConflict, "restore generation %d does not contain current %s ref %s and its committed parent configuration cannot project it; topology-removal restore is fail-closed", generation.Generation, prepared.label(), ref.Name)
				}
				if prepared.view != "beta" && prepared.view != "latest" {
					return prepared, withExitCode(ExitConflict, "restore generation %d would remove immutable or gated topology ref %s; topology-removal restore is fail-closed", generation.Generation, ref.Name)
				}
				removedTopologyLeaves = append(removedTopologyLeaves, leaf)
			}
		}
	}

	history, err := canonical.History()
	if err != nil {
		return prepared, withExitCode(ExitInternal, "read canonical history: %v", err)
	}
	historySet := make(map[plumbing.Hash]struct{}, len(history))
	for _, commit := range history {
		historySet[commit] = struct{}{}
	}
	refNames := make([]string, 0, len(leavesByRef))
	for name := range leavesByRef {
		refNames = append(refNames, name)
	}
	sort.Strings(refNames)

	var inputs []views.ProjectionInput
	var readers []io.ReadCloser
	var leaves []viewLeaf
	closeReaders := func() error {
		var closeErr error
		for _, reader := range readers {
			closeErr = errors.Join(closeErr, reader.Close())
		}
		readers = nil
		return closeErr
	}
	defer closeReaders()
	refCommits := make(map[string]plumbing.Hash, len(refNames))
	for _, name := range refNames {
		refState := leavesByRef[name].ref
		leaf := leavesByRef[name].leaf
		commit := plumbing.NewHash(refState.Commit)
		if _, exists := historySet[commit]; !exists {
			return prepared, withExitCode(ExitConflict, "historical ref %s commit %s is outside canonical HEAD history", name, commit)
		}
		canonicalPath, err := historicalLeafPath(prepared, leaf)
		if err != nil {
			return prepared, withExitCode(ExitInternal, "%v", err)
		}
		public := prepared.view != "snapshot" && cfg.Views[prepared.view].Access == "public"
		if err := validateViewAt(canonical, commit, canonicalPath, leaf, public); err != nil {
			return prepared, withExitCode(ExitVerification, "validate historical ref %s: %v", name, err)
		}
		digest, exists, err := hashCanonicalPathOptionalAt(canonical, commit, canonicalPath)
		if err != nil || !exists || digest != refState.ManifestSHA256 {
			return prepared, withExitCode(ExitVerification, "historical ref %s manifest digest=%s want=%s: %v", name, digest, refState.ManifestSHA256, err)
		}
		reader, err := canonical.OpenPathAt(commit, canonicalPath)
		if err != nil {
			return prepared, withExitCode(ExitInternal, "open historical ref %s: %v", name, err)
		}
		readers = append(readers, reader)
		inputs = append(inputs, views.ProjectionInput{Label: name, Reader: reader})
		leaves = append(leaves, leaf)
		refCommits[name] = commit
		prepared.refOverrides[name] = refState
	}
	if len(inputs) == 0 {
		return prepared, withExitCode(ExitConflict, "historical generation %d has no refs for intent %s", generation.Generation, prepared.label())
	}

	payloadManifest := filepath.Join(txDir, "restore-payload.tsv")
	payload, err := os.OpenFile(payloadManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return prepared, withExitCode(ExitInternal, "create restore payload manifest: %v", err)
	}
	entries, bytes, projectErr := views.ProjectManifest(inputs, payload)
	closeErr := errors.Join(payload.Sync(), payload.Close(), closeReaders())
	if projectErr != nil || closeErr != nil {
		return prepared, withExitCode(ExitVerification, "project historical intent %s: %v", prepared.label(), errors.Join(projectErr, closeErr))
	}
	if len(compatibilityRestores) != 0 {
		combinedPayload := filepath.Join(txDir, "restore-payload-with-compatibility.tsv")
		manifestPaths := append([]string{payloadManifest}, historicalCompatibilityManifestPaths(compatibilityRestores)...)
		if err := mergePublicationManifests(manifestPaths, combinedPayload, txDir); err != nil {
			return prepared, withExitCode(ExitVerification, "merge frozen compatibility candidates into historical payload: %v", err)
		}
		payloadManifest = combinedPayload
		for _, compatibility := range compatibilityRestores {
			entries += compatibility.entries
			bytes += compatibility.bytes
		}
	}

	restoreRelative, restoreRoot := historicalRestoreMaterializationPaths(cfg, target, generation)
	prepared.restoreRoot = restoreRoot
	source := materializeCanonicalSource{ID: prepared.view, Public: cfg.Views[prepared.view].Access == "public", RefCommits: refCommits}
	if prepared.view == "snapshot" {
		source.ID, source.Snapshot, source.Public = prepared.snapshotID, true, false
	}
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, "publish", source, leaves, restoreRoot, true, false)
	if err != nil {
		return prepared, withExitCode(ExitConflict, "begin historical selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	payloadReader, err := os.Open(payloadManifest)
	if err != nil {
		return prepared, withExitCode(ExitInternal, "%v", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustPayloadBefore); err != nil {
		_ = payloadReader.Close()
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	materialized, materializeErr := pool.MaterializeWithOptions(ctx, payloadReader, restoreRelative, repository.MaterializeOptions{Workers: values.workers})
	closeErr = payloadReader.Close()
	if materializeErr != nil || closeErr != nil {
		return prepared, withExitCode(ExitConflict, "materialize historical intent %s from CAS: %v", prepared.label(), errors.Join(materializeErr, closeErr))
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustPayloadAfter); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustExactReconcileBefore); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	reconciled, err := pool.ReconcileExact(ctx, payloadManifest, restoreRelative, values.workers, values.chunk)
	if err != nil {
		return prepared, withExitCode(ExitVerification, "reconcile historical intent %s: %v", prepared.label(), err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustExactReconcileAfter); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	for _, compatibility := range compatibilityRestores {
		physicalRoot := filepath.Join(restoreRoot, filepath.FromSlash(compatibility.identity.RouteRoot))
		if err := validateFrozenCompatibilityTree(ctx, cfg, canonical, compatibility.identity, physicalRoot, txDir, values.workers, values.chunk); err != nil {
			return prepared, withExitCode(ExitVerification, "validate historical compatibility %s exact protocol closure: %v", compatibility.identity.ID, err)
		}
	}
	metadata, err := materializeRepositoryMetadata(ctx, cfg, canonical, leaves, source, restoreRoot, txDir, privateKey, passphrase, values)
	if err != nil {
		return prepared, withExitCode(ExitVerification, "build historical repository metadata for %s: %v", prepared.label(), err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishBefore); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	if err := serving.PublishHostableTree(restoreRoot); err != nil {
		return prepared, withExitCode(ExitVerification, "publish hostable historical tree %s: %v", prepared.label(), err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishAfter); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	if err := completeMaterializedAssetUnits(values, cfg, leaves, source, restoreRoot); err != nil {
		return prepared, withExitCode(ExitConflict, "complete historical asset materialization units: %v", err)
	}
	selectionErr := finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, nil)
	selectionOwner = false
	if selectionErr != nil {
		return prepared, withExitCode(ExitConflict, "%v", selectionErr)
	}

	prepared.projections, prepared.yumOwnerLeaves, err = historicalPublicationProjections(leaves, prepared, restoreRelative)
	if err != nil {
		return prepared, withExitCode(ExitConfig, "%v", err)
	}
	prepared.projections = append(prepared.projections, historicalCompatibilityPublicationProjections(compatibilityRestores, restoreRelative)...)
	sort.Slice(prepared.projections, func(i, j int) bool { return prepared.projections[i].sourceRoot < prepared.projections[j].sourceRoot })
	if err := prepared.validateYUMOwnerVectors(); err != nil {
		return prepared, withExitCode(ExitVerification, "%v", err)
	}
	var manifests []string
	for index, projection := range prepared.projections {
		scanned := filepath.Join(txDir, fmt.Sprintf("restore-scan-%06d.tsv", index))
		if _, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{Path: projection.localRoot}, scanned, manifest.ScanOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}); err != nil {
			return prepared, withExitCode(ExitVerification, "scan reconstructed source %s: %v", projection.localRoot, err)
		}
		logical := filepath.Join(txDir, fmt.Sprintf("restore-logical-%06d.tsv", index))
		if err := rewriteManifestRoot(scanned, logical, projection.localRoot, projection.sourceRoot); err != nil {
			return prepared, withExitCode(ExitInternal, "map reconstructed source %s: %v", projection.localRoot, err)
		}
		manifests = append(manifests, logical)
		prepared.scopes = append(prepared.scopes, projection.sourceRoot)
	}
	prepared.manifestPath = filepath.Join(txDir, "restore-desired.tsv")
	if err := mergePublicationManifests(manifests, prepared.manifestPath, txDir); err != nil {
		return prepared, withExitCode(ExitInternal, "merge reconstructed historical intent: %v", err)
	}
	// A parent leaf absent from the historical intent contributes an empty exact
	// replace scope. No local tree is scanned: the exact parent content manifest
	// supplies path, size, and digest evidence. Asset leaves delete serving
	// objects; APT/YUM leaves delete only mutable index entry points and preserve
	// package payloads plus immutable generation archives.
	if len(removedTopologyLeaves) != 0 {
		removedProjections, removedYUMLeaves, err := historicalPublicationProjections(removedTopologyLeaves, prepared, restoreRoot)
		if err != nil {
			return prepared, withExitCode(ExitConfig, "project removed parent topology: %v", err)
		}
		removedPrepared := preparedPublication{view: prepared.view, yumOwnerLeaves: removedYUMLeaves}
		existingRoots := make(map[string]struct{}, len(prepared.projections))
		for _, projection := range prepared.projections {
			existingRoots[projection.sourceRoot] = struct{}{}
		}
		for _, projection := range removedProjections {
			if projection.repo.Type == "yum" {
				for _, channelProjection := range removedPrepared.yumChannelProjections(projection) {
					prepared.restoreRemovedChannelKeys[channelRemoteKey(prepared.view, channelProjection)] = true
				}
			}
			if _, covered := existingRoots[projection.sourceRoot]; covered {
				continue
			}
			prepared.scopes = append(prepared.scopes, projection.sourceRoot)
			prepared.restoreRemovedProjectionRoots[projection.sourceRoot] = true
			prepared.projections = append(prepared.projections, projection)
			if projection.repo.Type == "yum" {
				key := yumPublicationOwnerKey(projection.repo.ID, projection.arch)
				if prepared.yumOwnerLeaves == nil {
					prepared.yumOwnerLeaves = make(map[string][]viewLeaf)
				}
				prepared.yumOwnerLeaves[key] = append([]viewLeaf(nil), removedYUMLeaves[key]...)
			}
			existingRoots[projection.sourceRoot] = struct{}{}
		}
		sort.Slice(prepared.projections, func(i, j int) bool { return prepared.projections[i].sourceRoot < prepared.projections[j].sourceRoot })
	}
	if err := prepared.validateYUMOwnerVectors(); err != nil {
		return prepared, withExitCode(ExitVerification, "%v", err)
	}
	sort.Strings(prepared.scopes)
	fmt.Fprintf(stdout, "restore prepared target=%s source_generation=%d intent=%s refs=%d entries=%d bytes=%d linked=%d relinked=%d pruned=%d apt_suites=%d yum_repos=%d\n", target, generation.Generation, prepared.label(), len(prepared.refOverrides), entries, bytes, materialized.Linked, materialized.Relinked, reconciled.RemovedFiles, metadata.APTSuites, metadata.YUMRepos)
	return prepared, nil
}

type historicalLeaf struct {
	leaf viewLeaf
	ref  pub.RefState
}

func configuredHistoricalLeaves(cfg *config.Config, generation pub.TargetGeneration) (map[string]historicalLeaf, error) {
	view, snapshot := generation.IntentView, generation.IntentSnapshot
	if err := pub.ValidatePublicationIntent(view, snapshot); err != nil {
		return nil, err
	}
	configured := make(map[string]viewLeaf)
	for _, leaf := range selectedLeaves(cfg.Repos, commonFlags{}) {
		var ref plumbing.ReferenceName
		if view == "snapshot" {
			ref, _ = state.SnapshotRef(snapshot, leaf.repo.ID, leaf.os, leaf.arch)
		} else {
			ref, _ = state.ViewRef(view, leaf.repo.ID, leaf.os, leaf.arch)
		}
		configured[ref.String()] = leaf
	}
	result := make(map[string]historicalLeaf)
	for _, ref := range generation.Refs {
		if !publicationRefMatchesIntent(ref.Name, view, snapshot) {
			continue
		}
		leaf, exists := configured[ref.Name]
		if !exists {
			return nil, fmt.Errorf("historical generation ref %s is not representable by current configuration", ref.Name)
		}
		if view != "snapshot" && !viewIncludesRepo(cfg.Views[view], leaf.repo.ID) {
			return nil, fmt.Errorf("historical generation ref %s is excluded from current view configuration", ref.Name)
		}
		result[ref.Name] = historicalLeaf{leaf: leaf, ref: ref}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("historical generation %d has no refs for intent %s/%s", generation.Generation, view, snapshot)
	}
	return result, nil
}

// configuredPublicationLeaves freezes the only topology-removal authority a
// restore may use. It maps exact publication refs back to the current config;
// an unrepresentable ref is never guessed from its path text.
func configuredPublicationLeaves(cfg *config.Config, view, snapshot string) (map[string]viewLeaf, error) {
	if err := pub.ValidatePublicationIntent(view, snapshot); err != nil {
		return nil, err
	}
	configured := make(map[string]viewLeaf)
	for _, leaf := range selectedLeaves(cfg.Repos, commonFlags{}) {
		var ref plumbing.ReferenceName
		var err error
		if view == "snapshot" {
			ref, err = state.SnapshotRef(snapshot, leaf.repo.ID, leaf.os, leaf.arch)
		} else {
			ref, err = state.ViewRef(view, leaf.repo.ID, leaf.os, leaf.arch)
		}
		if err != nil {
			return nil, err
		}
		if _, duplicate := configured[ref.String()]; duplicate {
			return nil, fmt.Errorf("configuration maps duplicate publication ref %s", ref)
		}
		configured[ref.String()] = leaf
	}
	return configured, nil
}

func configuredPublicationLeavesAt(canonical *state.Store, commit plumbing.Hash, runtime *config.Config, view, snapshot string) (map[string]viewLeaf, error) {
	committed, err := canonicalConfigurationAt(canonical, commit, runtime)
	if err != nil {
		return nil, err
	}
	return configuredPublicationLeaves(committed, view, snapshot)
}

func canonicalConfigurationAt(canonical *state.Store, commit plumbing.Hash, runtime *config.Config) (*config.Config, error) {
	if canonical == nil || commit.IsZero() {
		return nil, errors.New("committed parent configuration is unavailable")
	}
	body, exists, err := readCanonicalConfigBytesAt(canonical, commit)
	if err != nil || !exists {
		return nil, errors.Join(err, errors.New("committed parent config/sow.yaml is missing"))
	}
	committed, err := config.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decode committed parent configuration: %w", err)
	}
	if runtime != nil {
		committed.Path = runtime.Path
		committed.Root = runtime.Root
	}
	return committed, nil
}

func historicalLeafPath(prepared preparedPublication, leaf viewLeaf) (string, error) {
	if prepared.view == "snapshot" {
		return state.SnapshotPath(prepared.snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
	}
	return state.ViewPath(prepared.view, leaf.repo.ID, leaf.os, leaf.arch)
}

func historicalPublicationProjections(leaves []viewLeaf, prepared preparedPublication, restoreRoot string) ([]publicationProjection, map[string][]viewLeaf, error) {
	var projections []publicationProjection
	seenAPT := make(map[string]struct{})
	seenAsset := make(map[string]struct{})
	seenYUM := make(map[string]struct{})
	yumOwnerLeaves := make(map[string][]viewLeaf)
	for _, leaf := range leaves {
		logicalBase := ""
		if prepared.view == "snapshot" {
			logicalBase = defaultMaterializationTarget(prepared.snapshotID, true)
		}
		switch leaf.repo.Type {
		case "apt":
			if _, duplicate := seenAPT[leaf.repo.ID]; duplicate {
				continue
			}
			seenAPT[leaf.repo.ID] = struct{}{}
			logical := repositoryViewTarget(leaf.repo.Path, prepared.view)
			if prepared.view == "snapshot" {
				logical = path.Join(logicalBase, leaf.repo.Path)
			}
			projections = append(projections, publicationProjection{
				view: prepared.view, repo: leaf.repo, sourceRoot: logical, localRoot: path.Join(restoreRoot, leaf.repo.Path),
				canonicalRoot: leaf.repo.Path, remoteRoot: leaf.repo.Path, legacyRoot: leaf.repo.Path,
			})
		case "asset":
			if _, duplicate := seenAsset[leaf.repo.ID]; duplicate {
				continue
			}
			seenAsset[leaf.repo.ID] = struct{}{}
			logical := repositoryViewTarget(leaf.repo.Path, prepared.view)
			if prepared.view == "snapshot" {
				logical = path.Join(logicalBase, leaf.repo.Path)
			}
			projections = append(projections, publicationProjection{
				view: prepared.view, repo: leaf.repo, os: "all", arch: "all", sourceRoot: logical, localRoot: path.Join(restoreRoot, leaf.repo.Path),
				canonicalRoot: leaf.repo.Path, remoteRoot: leaf.repo.AssetPublicRoot(), legacyRoot: leaf.repo.Path,
			})
		case "yum":
			legacy, err := leaf.repo.PathForArch(leaf.arch)
			if err != nil {
				return nil, nil, err
			}
			ownerKey := yumPublicationOwnerKey(leaf.repo.ID, leaf.arch)
			yumOwnerLeaves[ownerKey] = append(yumOwnerLeaves[ownerKey], leaf)
			if _, duplicate := seenYUM[ownerKey]; duplicate {
				continue
			}
			seenYUM[ownerKey] = struct{}{}
			logical := repositoryViewTarget(legacy, prepared.view)
			if prepared.view == "snapshot" {
				logical = path.Join(logicalBase, legacy)
			}
			projections = append(projections, publicationProjection{
				view: prepared.view, repo: leaf.repo, os: leaf.os, arch: leaf.arch, sourceRoot: logical, localRoot: path.Join(restoreRoot, legacy),
				canonicalRoot: legacy, remoteRoot: legacy, legacyRoot: legacy,
			})
		default:
			return nil, nil, fmt.Errorf("unsupported historical repository type %s", leaf.repo.Type)
		}
	}
	sort.Slice(projections, func(i, j int) bool { return projections[i].sourceRoot < projections[j].sourceRoot })
	for key := range yumOwnerLeaves {
		sort.Slice(yumOwnerLeaves[key], func(i, j int) bool {
			return servingLeafKey(yumOwnerLeaves[key][i].repo.ID, yumOwnerLeaves[key][i].os, yumOwnerLeaves[key][i].arch) < servingLeafKey(yumOwnerLeaves[key][j].repo.ID, yumOwnerLeaves[key][j].os, yumOwnerLeaves[key][j].arch)
		})
	}
	return projections, yumOwnerLeaves, nil
}

func rewriteManifestRoot(sourcePath, destinationPath, sourceRoot, destinationRoot string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		source.Close()
		return err
	}
	reader := manifest.NewReader(source)
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.Join(readErr, source.Close(), destination.Close())
		}
		prefix := strings.TrimSuffix(sourceRoot, "/") + "/"
		if !strings.HasPrefix(entry.Path, prefix) {
			return errors.Join(fmt.Errorf("manifest path %s is outside %s", entry.Path, sourceRoot), source.Close(), destination.Close())
		}
		entry.Path = path.Join(destinationRoot, strings.TrimPrefix(entry.Path, prefix))
		if err := manifest.WriteEntry(destination, entry); err != nil {
			return errors.Join(err, source.Close(), destination.Close())
		}
	}
	return errors.Join(source.Close(), destination.Sync(), destination.Close())
}

func decodeRestoreAudit(body []byte) (restoreAuditRecord, error) {
	var record restoreAuditRecord
	if len(body) == 0 || len(body) > 4<<20 {
		return record, errors.New("restore audit must contain between 1 byte and 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode restore audit: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return record, errors.New("restore audit has trailing JSON content")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(body, canonical) {
		return record, errors.Join(err, errors.New("restore audit is not canonical JSON"))
	}
	if record.Schema != restoreAuditSchema {
		return record, fmt.Errorf("restore audit schema %q is not %q", record.Schema, restoreAuditSchema)
	}
	if err := pub.TargetName(record.Target).Validate(); err != nil {
		return record, err
	}
	if record.Generation == 0 || record.SourceGeneration == 0 {
		return record, errors.New("restore audit generations must be positive")
	}
	if err := pub.ValidatePublicationIntent(record.IntentView, record.IntentSnapshot); err != nil {
		return record, err
	}
	if _, err := hex.DecodeString(record.SourceGenerationSHA256); err != nil || len(record.SourceGenerationSHA256) != sha256.Size*2 {
		return record, errors.New("restore audit source generation sha256 is invalid")
	}
	if _, err := hex.DecodeString(record.SourcePlanSHA256); err != nil || len(record.SourcePlanSHA256) != sha256.Size*2 {
		return record, errors.New("restore audit source plan sha256 is invalid")
	}
	if plumbing.NewHash(record.SourceStateCommit).IsZero() || len(record.SourceStateCommit) != 40 {
		return record, errors.New("restore audit source state commit is invalid")
	}
	if sourceGeneration, ok := restoreSourceGenerationFromTransactionID(record.TransactionID); !ok || sourceGeneration != record.SourceGeneration {
		return record, errors.New("restore audit transaction does not bind its source generation")
	}
	if len(record.Refs) == 0 {
		return record, errors.New("restore audit has no source refs")
	}
	for index := range record.Refs {
		ref := record.Refs[index]
		if index != 0 && record.Refs[index-1].Name >= ref.Name {
			return record, errors.New("restore audit refs are not strictly sorted")
		}
		if plumbing.ReferenceName(ref.Name).Validate() != nil || plumbing.NewHash(ref.Commit).IsZero() || len(ref.Commit) != 40 {
			return record, fmt.Errorf("restore audit ref %q is invalid", ref.Name)
		}
		if _, err := hex.DecodeString(ref.ManifestSHA256); err != nil || len(ref.ManifestSHA256) != sha256.Size*2 {
			return record, fmt.Errorf("restore audit ref %q manifest sha256 is invalid", ref.Name)
		}
	}
	return record, nil
}

func currentGenerationRestoresHistoricalSource(canonical *state.Store, target string, currentGeneration uint64, historical historicalTargetPublication) (bool, error) {
	name := remoteStatePath(target, filepath.ToSlash(filepath.Join("restores", fmt.Sprintf("%020d.json", currentGeneration))))
	reader, err := canonical.OpenPath(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return false, errors.Join(readErr, closeErr)
	}
	record, err := decodeRestoreAudit(body)
	if err != nil {
		return false, fmt.Errorf("validate current generation restore audit %s: %w", name, err)
	}
	if record.Target != target || record.Generation != currentGeneration {
		return false, fmt.Errorf("current generation restore audit %s does not bind target/generation", name)
	}
	if record.SourceGeneration != historical.Generation.Generation ||
		record.SourceGenerationSHA256 != historical.SHA256 ||
		record.SourcePlanSHA256 != historical.PlanSHA256 ||
		record.SourceStateCommit != historical.StateCommit.String() ||
		record.IntentView != historical.Generation.IntentView ||
		record.IntentSnapshot != historical.Generation.IntentSnapshot {
		return false, nil
	}
	expectedRefs := make([]pub.RefState, 0, len(historical.Generation.Refs))
	for _, ref := range historical.Generation.Refs {
		if publicationRefMatchesIntent(ref.Name, historical.Generation.IntentView, historical.Generation.IntentSnapshot) {
			expectedRefs = append(expectedRefs, ref)
		}
	}
	sort.Slice(expectedRefs, func(i, j int) bool { return expectedRefs[i].Name < expectedRefs[j].Name })
	return sameRefStates(record.Refs, expectedRefs), nil
}

func encodeRestoreAudit(publication targetPublication) ([]byte, error) {
	if publication.restore == nil {
		return nil, errors.New("publication has no restore source")
	}
	source := publication.restore
	decodedSHA, shaErr := hex.DecodeString(source.SHA256)
	decodedPlanSHA, planSHAErr := hex.DecodeString(source.PlanSHA256)
	if source.Generation == 0 || shaErr != nil || planSHAErr != nil || len(decodedSHA) != sha256.Size || len(decodedPlanSHA) != sha256.Size || plumbing.NewHash(source.Commit).IsZero() {
		return nil, errors.New("invalid restore audit source")
	}
	refs := append([]pub.RefState(nil), source.Refs...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	record := restoreAuditRecord{
		Schema: restoreAuditSchema, Target: publication.target,
		Generation:       publication.request.Generation.Generation,
		SourceGeneration: source.Generation, SourceGenerationSHA256: source.SHA256,
		SourcePlanSHA256: source.PlanSHA256, SourceStateCommit: source.Commit, IntentView: publication.request.Generation.IntentView,
		IntentSnapshot: publication.request.Generation.IntentSnapshot,
		TransactionID:  publication.request.TransactionID, Refs: refs,
	}
	return json.Marshal(record)
}
