package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/yumrepo"
)

// verificationHTTPClient is nil in production. Protocol-level tests replace
// it without bypassing URL, redirect, signature, or byte validation.
var verificationHTTPClient *http.Client

var proVerificationTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)

type committedVerificationState struct {
	generation pub.TargetGeneration
	checkpoint pub.Checkpoint
	plan       pub.Plan
}

type verificationStateError struct {
	code     string
	category verify.Category
	message  string
}

type aggregateVerificationState struct {
	generation pub.TargetGeneration
	inventory  map[string]struct{}
}

func loadCurrentAggregateVerificationState(canonical *state.Store, target string, inventoryCandidates map[string]struct{}) (aggregateVerificationState, error) {
	var result aggregateVerificationState
	generation, generationBody, generationExists, generationErr := readLocalTargetGeneration(canonical, target)
	checkpoint, checkpointBody, checkpointExists, checkpointErr := readLocalTargetCheckpoint(canonical, target)
	planBody, planExists, planErr := readOptionalCanonical(canonical, remoteStatePath(target, "plan.json"))
	if generationErr != nil || checkpointErr != nil || planErr != nil || !generationExists || !checkpointExists || !planExists {
		return result, &verificationStateError{code: "REMOTE_AGGREGATE_CLOSURE_MISSING", category: verify.CategoryCoverage, message: "current target aggregate generation, checkpoint, and plan are required"}
	}
	plan, decodeErr := pub.DecodePlan(planBody)
	var bindingErr error
	if decodeErr == nil {
		bindingErr = validateCanonicalCheckpointPlanBinding(canonical, target, generation, generationBody, checkpoint, checkpointBody, plan)
	}
	if decodeErr != nil || bindingErr != nil || len(plan.Verify) != len(plan.Objects) || checkpoint.Phase != pub.PhaseCheckpointCommitted ||
		checkpoint.Generation != generation.Generation || checkpoint.ParentGeneration != generation.ParentGeneration ||
		checkpoint.GenerationSHA256 != digestBytesCLI(generationBody) || checkpoint.DesiredCommit != generation.DesiredCommit ||
		checkpoint.ContentManifestSHA256 != generation.ContentManifestSHA256 ||
		!pub.SamePublicationIntent(checkpoint.IntentView, checkpoint.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) {
		return result, &verificationStateError{code: "REMOTE_AGGREGATE_CLOSURE_DRIFT", category: verify.CategoryDrift, message: "current target aggregate generation, checkpoint, and plan disagree"}
	}
	inventoryFile, inventoryExists, inventoryErr := openOptionalCanonical(canonical, remoteStatePath(target, "inventory.tsv"))
	if inventoryErr != nil || !inventoryExists {
		return result, &verificationStateError{code: "REMOTE_AGGREGATE_INVENTORY_MISSING", category: verify.CategoryCoverage, message: "current target aggregate inventory is required"}
	}
	defer inventoryFile.Close()
	// Inventory can contain millions of keys. Keep only exact change-set keys
	// needed to decide whether a historical negative was superseded.
	inventory := make(map[string]struct{}, len(inventoryCandidates))
	reader := manifest.NewReader(inventoryFile)
	previous := ""
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || previous != "" && entry.Path <= previous {
			return result, &verificationStateError{code: "REMOTE_AGGREGATE_INVENTORY_INVALID", category: verify.CategoryIntegrity, message: "current target aggregate inventory is invalid"}
		}
		previous = entry.Path
		if _, candidate := inventoryCandidates[entry.Path]; candidate {
			inventory[entry.Path] = struct{}{}
		}
	}
	result.generation, result.inventory = generation, inventory
	return result, nil
}

func loadCurrentAggregateVerificationStateForConfig(cfg *config.Config, canonical *state.Store, target string, inventoryCandidates map[string]struct{}) (aggregateVerificationState, error) {
	result, err := loadCurrentAggregateVerificationState(canonical, target, inventoryCandidates)
	if err != nil {
		return result, err
	}
	if err := validatePublicationChannelOwners(cfg, target, result.generation); err != nil {
		return aggregateVerificationState{}, &verificationStateError{code: "REMOTE_CHANNEL_OWNER_DRIFT", category: verify.CategoryDrift, message: err.Error()}
	}
	if err := validateGenerationCompatibility(cfg, canonical, target, result.generation); err != nil {
		return aggregateVerificationState{}, &verificationStateError{code: "REMOTE_COMPATIBILITY_IDENTITY_DRIFT", category: verify.CategoryDrift, message: err.Error()}
	}
	return result, nil
}

func snapshotIDFromAbsenceRoute(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	routePath := "/" + strings.TrimPrefix(u.Path, "/")
	const marker = "/_sow/v1/snapshots/"
	index := strings.Index(routePath, marker)
	if index < 0 {
		return "", false
	}
	remainder := strings.TrimPrefix(routePath[index:], marker)
	snapshotID, suffix, found := strings.Cut(remainder, "/")
	if !found || suffix != "_route.json" || pub.ValidatePublicationIntent("snapshot", snapshotID) != nil {
		return "", false
	}
	return snapshotID, true
}

func activeSnapshotIDs(generation pub.TargetGeneration) map[string]struct{} {
	result := make(map[string]struct{})
	for _, ref := range generation.Refs {
		if snapshotID, ok := snapshotIDFromPublicationRef(ref.Name); ok {
			result[snapshotID] = struct{}{}
		}
	}
	return result
}

func filterSupersededSnapshotAbsences(expectations []pub.VerifyAbsentObject, aggregate aggregateVerificationState) []pub.VerifyAbsentObject {
	active := activeSnapshotIDs(aggregate.generation)
	result := make([]pub.VerifyAbsentObject, 0, len(expectations))
	for _, expectation := range expectations {
		snapshotID, snapshotRoute := snapshotIDFromAbsenceRoute(expectation.URL)
		_, restored := active[snapshotID]
		_, routePresent := aggregate.inventory[path.Join(".sow/snapshots", snapshotID+".json")]
		if snapshotRoute && restored && routePresent {
			continue
		}
		result = append(result, expectation)
	}
	return result
}

func filterSupersededSnapshotDeletions(deletions []pub.PlannedDelete, aggregate aggregateVerificationState) []pub.PlannedDelete {
	active := activeSnapshotIDs(aggregate.generation)
	result := make([]pub.PlannedDelete, 0, len(deletions))
	for _, deletion := range deletions {
		snapshotID, snapshotOwned := remoteSnapshotOwnedKey(deletion.RemoteKey)
		if !snapshotOwned {
			snapshotID, snapshotOwned = snapshotIDFromAbsenceRoute(deletion.CDNPath)
		}
		_, restored := active[snapshotID]
		_, keyPresent := aggregate.inventory[deletion.RemoteKey]
		if snapshotOwned && restored && keyPresent {
			continue
		}
		result = append(result, deletion)
	}
	return result
}

func snapshotAbsenceInventoryCandidates(expectations []pub.VerifyAbsentObject) map[string]struct{} {
	result := make(map[string]struct{}, len(expectations))
	for _, expectation := range expectations {
		if snapshotID, ok := snapshotIDFromAbsenceRoute(expectation.URL); ok {
			result[path.Join(".sow/snapshots", snapshotID+".json")] = struct{}{}
		}
	}
	return result
}

func snapshotDeletionInventoryCandidates(deletions []pub.PlannedDelete) map[string]struct{} {
	result := make(map[string]struct{}, len(deletions))
	for _, deletion := range deletions {
		if _, ok := remoteSnapshotOwnedKey(deletion.RemoteKey); ok {
			result[deletion.RemoteKey] = struct{}{}
		}
	}
	return result
}

func (e *verificationStateError) Error() string { return e.message }

func generationRepositoryTrustMatches(cfg *config.Config, generation pub.TargetGeneration) (bool, error) {
	current, err := repositoryTrustAnchorSHA256ForRefs(cfg, generation.Refs)
	if err != nil {
		return false, err
	}
	return generation.RepositoryKeySHA256 == current, nil
}

func loadCommittedVerificationState(canonical *state.Store, target, intentView, intentSnapshot string) (committedVerificationState, error) {
	var result committedVerificationState
	generationPath, err := remoteIntentStatePath(target, intentView, intentSnapshot, "generation.json")
	if err != nil {
		return result, &verificationStateError{code: "REMOTE_INTENT_INVALID", category: verify.CategoryCoverage, message: "selected publication intent is invalid"}
	}
	checkpointPath, _ := remoteIntentStatePath(target, intentView, intentSnapshot, "checkpoint.json")
	planPath, _ := remoteIntentStatePath(target, intentView, intentSnapshot, "plan.json")
	generationBody, generationExists, err := readOptionalCanonical(canonical, generationPath)
	if err != nil {
		return result, &verificationStateError{code: "REMOTE_GENERATION_INVALID", category: verify.CategoryIntegrity, message: "canonical target generation is invalid"}
	}
	checkpointBody, checkpointExists, err := readOptionalCanonical(canonical, checkpointPath)
	if err != nil {
		return result, &verificationStateError{code: "REMOTE_CHECKPOINT_INVALID", category: verify.CategoryIntegrity, message: "canonical target checkpoint is invalid"}
	}
	planBody, planExists, err := readOptionalCanonical(canonical, planPath)
	if err != nil {
		return result, &verificationStateError{code: "REMOTE_PLAN_UNREADABLE", category: verify.CategoryCoverage, message: "canonical publication plan cannot be read"}
	}
	// Schema-v1 states written before intent projections have only the
	// target-global triplet. It is safe to use that triplet only when its
	// generation belongs to the requested intent; a subsequent publication of
	// another view must never masquerade as coverage.
	if !generationExists && !checkpointExists && !planExists {
		legacyGeneration, legacyGenerationBody, legacyGenerationExists, legacyErr := readLocalTargetGeneration(canonical, target)
		legacyCheckpoint, legacyCheckpointBody, legacyCheckpointExists, checkpointErr := readLocalTargetCheckpoint(canonical, target)
		legacyPlanBody, legacyPlanExists, planErr := readOptionalCanonical(canonical, remoteStatePath(target, "plan.json"))
		if legacyErr == nil && checkpointErr == nil && planErr == nil && legacyGenerationExists && legacyCheckpointExists && legacyPlanExists &&
			pub.SamePublicationIntent(legacyGeneration.IntentView, legacyGeneration.IntentSnapshot, intentView, intentSnapshot) &&
			pub.SamePublicationIntent(legacyCheckpoint.IntentView, legacyCheckpoint.IntentSnapshot, intentView, intentSnapshot) {
			generationBody, generationExists = legacyGenerationBody, true
			checkpointBody, checkpointExists = legacyCheckpointBody, true
			planBody, planExists = legacyPlanBody, true
		}
	}
	if !generationExists || !checkpointExists || !planExists {
		return result, &verificationStateError{code: "REMOTE_PLAN_COVERAGE_MISSING", category: verify.CategoryCoverage, message: "the selected intent's committed generation, checkpoint, and publication plan are required"}
	}
	generation, err := pub.DecodeTargetGeneration(generationBody)
	if err != nil || string(generation.Target) != target {
		return result, &verificationStateError{code: "REMOTE_GENERATION_INVALID", category: verify.CategoryIntegrity, message: "canonical target generation is invalid"}
	}
	checkpoint, err := pub.DecodeCheckpoint(checkpointBody)
	if err != nil || string(checkpoint.Target) != target {
		return result, &verificationStateError{code: "REMOTE_CHECKPOINT_INVALID", category: verify.CategoryIntegrity, message: "canonical target checkpoint is invalid"}
	}
	plan, err := pub.DecodePlan(planBody)
	if err != nil {
		return result, &verificationStateError{code: "REMOTE_PLAN_INVALID", category: verify.CategoryIntegrity, message: "canonical publication plan is invalid"}
	}
	if err := validateCanonicalCheckpointPlanBinding(canonical, target, generation, generationBody, checkpoint, checkpointBody, plan); err != nil {
		return result, &verificationStateError{code: "REMOTE_PLAN_BINDING_DRIFT", category: verify.CategoryIntegrity, message: "canonical publication plan disagrees with its committed checkpoint"}
	}
	if string(generation.Target) != target || string(checkpoint.Target) != target || checkpoint.Phase != pub.PhaseCheckpointCommitted ||
		checkpoint.Generation != generation.Generation || checkpoint.ParentGeneration != generation.ParentGeneration ||
		!pub.SamePublicationIntent(checkpoint.IntentView, checkpoint.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) ||
		checkpoint.GenerationSHA256 != digestBytesCLI(generationBody) || checkpoint.DesiredCommit != generation.DesiredCommit || checkpoint.ContentManifestSHA256 != generation.ContentManifestSHA256 {
		return result, &verificationStateError{code: "REMOTE_COMMIT_CLOSURE_DRIFT", category: verify.CategoryDrift, message: "canonical target checkpoint and generation disagree"}
	}
	if len(plan.Verify) != len(plan.Objects) {
		return result, &verificationStateError{code: "REMOTE_PLAN_VERIFY_COVERAGE_MISSING", category: verify.CategoryCoverage, message: "last committed plan lacks a complete verification set"}
	}
	result.generation, result.checkpoint, result.plan = generation, checkpoint, plan
	return result, nil
}

func loadCommittedVerificationStateForConfig(cfg *config.Config, canonical *state.Store, target, intentView, intentSnapshot string) (committedVerificationState, error) {
	result, err := loadCommittedVerificationState(canonical, target, intentView, intentSnapshot)
	if err != nil {
		return result, err
	}
	if err := validatePublicationChannelOwners(cfg, target, result.generation); err != nil {
		return committedVerificationState{}, &verificationStateError{code: "REMOTE_CHANNEL_OWNER_DRIFT", category: verify.CategoryDrift, message: err.Error()}
	}
	if err := validateGenerationCompatibility(cfg, canonical, target, result.generation); err != nil {
		return committedVerificationState{}, &verificationStateError{code: "REMOTE_COMPATIBILITY_IDENTITY_DRIFT", category: verify.CategoryDrift, message: err.Error()}
	}
	if err := validateCommittedCompatibilityPublicationClosure(canonical, target, result.generation, result.plan); err != nil {
		return committedVerificationState{}, &verificationStateError{code: "REMOTE_COMPATIBILITY_CLOSURE_DRIFT", category: verify.CategoryIntegrity, message: err.Error()}
	}
	return result, nil
}

func buildSnapshotL2Checks(cfg *config.Config, canonical *state.Store, repos []config.Repo, snapshotID string, values commonFlags, selectedTargets []string, networkFailure *atomic.Bool) ([]verify.Check, error) {
	leaves, err := selectedSnapshotLeaves(cfg, repos, values, snapshotID)
	if err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return []verify.Check{missingCheck("remote/snapshot/"+snapshotID+"/coverage", verify.LayerL2, "SNAPSHOT_REF_COVERAGE_MISSING", snapshotID, "selectors matched no repository leaves for this snapshot suite")}, nil
	}
	var checks []verify.Check
	for _, target := range verifyTargetNames(cfg, selectedTargets) {
		targetLeaves, err := selectedVerificationSnapshotLeaves(cfg, repos, target, snapshotID, values)
		if err != nil {
			return nil, err
		}
		if len(targetLeaves) == 0 {
			continue
		}
		publication, stateErr := loadCommittedVerificationStateForConfig(cfg, canonical, target, "snapshot", snapshotID)
		id := "remote/" + target + "/snapshot/" + snapshotID
		if stateErr != nil {
			checks = append(checks, verificationStateCheck(id, verify.LayerL2, target, stateErr))
			continue
		}
		configSHA, err := publicationConfigSHA256ForGeneration(cfg, publication.generation)
		if err != nil {
			return nil, err
		}
		if publication.generation.IntentView != "snapshot" || publication.generation.IntentSnapshot != snapshotID || publication.checkpoint.IntentView != "snapshot" || publication.checkpoint.IntentSnapshot != snapshotID {
			checks = append(checks, verificationStateCheck(id, verify.LayerL2, target, &verificationStateError{code: "REMOTE_SNAPSHOT_INTENT_DRIFT", category: verify.CategoryDrift, message: "committed generation or checkpoint belongs to another snapshot intent"}))
			continue
		}
		if publication.generation.ConfigSHA256 != configSHA {
			checks = append(checks, verificationStateCheck(id, verify.LayerL2, target, &verificationStateError{code: "REMOTE_CONFIG_DRIFT", category: verify.CategoryDrift, message: "current configuration differs from the committed snapshot generation"}))
			continue
		}
		keyMatches, err := generationRepositoryTrustMatches(cfg, publication.generation)
		if err != nil {
			return nil, err
		}
		if !keyMatches {
			checks = append(checks, verificationStateCheck(id, verify.LayerL2, target, &verificationStateError{code: "REMOTE_REPOSITORY_KEY_DRIFT", category: verify.CategoryDrift, message: "current repository public key differs from the committed generation"}))
			continue
		}
		deletionsCopy := append([]pub.PlannedDelete(nil), publication.plan.Deletes...)
		if len(deletionsCopy) != 0 {
			aggregate, aggregateErr := loadCurrentAggregateVerificationStateForConfig(cfg, canonical, target, snapshotDeletionInventoryCandidates(deletionsCopy))
			if aggregateErr != nil {
				checks = append(checks, verificationStateCheck(id, verify.LayerL2, target, aggregateErr))
				continue
			}
			deletionsCopy = filterSupersededSnapshotDeletions(deletionsCopy, aggregate)
		}
		client, err := newPublishTargetClient(cfg, target, "snapshot", false)
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", target, err)
		}
		generationBody, err := publication.generation.Canonical()
		if err != nil {
			return nil, err
		}
		checkpointBody, err := publication.checkpoint.Canonical()
		if err != nil {
			return nil, err
		}
		targetCopy, publicationCopy, clientCopy := target, publication, client
		generationBodyCopy, checkpointBodyCopy := append([]byte(nil), generationBody...), append([]byte(nil), checkpointBody...)
		leavesCopy := append([]viewLeaf(nil), targetLeaves...)
		checks = append(checks, verify.CheckFunc{CheckID: id, CheckLayer: verify.LayerL2, Run: func(ctx context.Context, recorder *verify.Recorder) error {
			byName := make(map[string]pub.RefState, len(publicationCopy.generation.Refs))
			for _, ref := range publicationCopy.generation.Refs {
				byName[ref.Name] = ref
			}
			for _, leaf := range leavesCopy {
				desiredRef, _ := state.SnapshotRef(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
				desiredCommit, desiredExists, readErr := canonical.Ref(desiredRef)
				if readErr != nil {
					return readErr
				}
				if !desiredExists {
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryCoverage, "SNAPSHOT_REF_MISSING", desiredRef.String(), "immutable local snapshot ref is missing")
					continue
				}
				expected, covered := byName[desiredRef.String()]
				if !covered {
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryCoverage, "REMOTE_SNAPSHOT_REF_COVERAGE_MISSING", desiredRef.String(), "committed snapshot generation does not cover this selected leaf")
					continue
				}
				if expected.Commit != desiredCommit.String() {
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "SNAPSHOT_IMMUTABLE_REF_DRIFT", desiredRef.String(), "immutable snapshot ref no longer names the published canonical commit")
				}
				canonicalPath, _ := state.SnapshotPath(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
				reader, openErr := canonical.OpenPathAt(desiredCommit, canonicalPath)
				if openErr != nil {
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "SNAPSHOT_MANIFEST_MISSING", desiredRef.String(), "snapshot ref cannot open its canonical manifest")
					continue
				}
				digest, hashErr := hashReader(reader)
				if hashErr != nil {
					return hashErr
				}
				if digest != expected.ManifestSHA256 {
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "SNAPSHOT_MANIFEST_DRIFT", desiredRef.String(), "snapshot manifest differs from the committed generation digest")
				}
				remoteRef, _ := state.RemoteRef(targetCopy, snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
				remoteCommit, remoteExists, remoteErr := canonical.Ref(remoteRef)
				if remoteErr != nil {
					return remoteErr
				}
				if !remoteExists || remoteCommit.String() != expected.Commit {
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_SNAPSHOT_REF_DRIFT", remoteRef.String(), "canonical target snapshot ref differs from the committed generation")
				}
			}

			remoteCheckpoint, remoteErr := clientCopy.getControl(ctx, pub.CheckpointKey)
			if remoteErr != nil {
				networkFailure.Store(true)
				return remoteErr
			}
			if !remoteCheckpoint.Exists {
				addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_CHECKPOINT_MISSING", targetCopy, "remote checkpoint is missing")
			} else {
				current, decodeErr := pub.DecodeCheckpoint(remoteCheckpoint.Body)
				switch {
				case decodeErr != nil || string(current.Target) != targetCopy:
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "REMOTE_CHECKPOINT_INVALID", targetCopy, "remote checkpoint is invalid")
				case current.Generation < publicationCopy.generation.Generation:
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_CHECKPOINT_ROLLBACK", targetCopy, "remote checkpoint predates the selected snapshot generation")
				case current.Generation == publicationCopy.generation.Generation && !bytes.Equal(remoteCheckpoint.Body, checkpointBodyCopy):
					addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_CHECKPOINT_CHANGED", targetCopy, "remote checkpoint bytes differ from the selected snapshot checkpoint")
				}
			}
			generationKey, _ := pub.GenerationKey(publicationCopy.generation.Generation)
			remoteGeneration, remoteErr := clientCopy.getControl(ctx, generationKey)
			if remoteErr != nil {
				networkFailure.Store(true)
				return remoteErr
			}
			if !remoteGeneration.Exists {
				addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_GENERATION_MISSING", generationKey, "immutable snapshot generation is missing")
			} else if !bytes.Equal(remoteGeneration.Body, generationBodyCopy) {
				addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_GENERATION_CHANGED", generationKey, "immutable snapshot generation bytes differ from canonical state")
			}
			if err := auditPlanObjectHeads(ctx, clientCopy, publicationCopy.plan.Objects, recorder); err != nil {
				networkFailure.Store(true)
				return err
			}
			if err := auditPlanDeletionHeads(ctx, clientCopy, deletionsCopy, recorder); err != nil {
				networkFailure.Store(true)
				return err
			}
			return nil
		}})
	}
	if len(checks) == 0 {
		checks = append(checks, missingCheck("remote/snapshot/coverage", verify.LayerL2, "REMOTE_TARGET_COVERAGE_MISSING", snapshotID, "no configured target can execute a snapshot L2 audit"))
	}
	return checks, nil
}

func buildL3Checks(cfg *config.Config, canonical *state.Store, repos []config.Repo, viewsToCheck []string, values commonFlags, selectedTargets []string, proToken []byte, networkFailure *atomic.Bool) ([]verify.Check, error) {
	targets := verifyTargetNames(cfg, selectedTargets)
	var checks []verify.Check
	for _, target := range targets {
		for _, viewName := range viewsToCheck {
			publication, stateErr := loadCommittedVerificationStateForConfig(cfg, canonical, target, viewName, "")
			id := "cdn/" + target + "/" + viewName
			if stateErr != nil {
				checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, stateErr))
				continue
			}
			configSHA, err := publicationConfigSHA256ForGeneration(cfg, publication.generation)
			if err != nil {
				return nil, err
			}
			if publication.generation.ConfigSHA256 != configSHA {
				checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, &verificationStateError{code: "REMOTE_CONFIG_DRIFT", category: verify.CategoryDrift, message: "current configuration differs from the committed publication generation"}))
				continue
			}
			keyMatches, err := generationRepositoryTrustMatches(cfg, publication.generation)
			if err != nil {
				return nil, err
			}
			if !keyMatches {
				checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, &verificationStateError{code: "REMOTE_REPOSITORY_KEY_DRIFT", category: verify.CategoryDrift, message: "current repository public key differs from the committed generation"}))
				continue
			}
			if publication.generation.IntentView != viewName {
				checks = append(checks, missingCheck(id, verify.LayerL3, "REMOTE_PLAN_VIEW_COVERAGE_MISSING", target+"/"+viewName, "last committed publication plan belongs to another view"))
				continue
			}
			if err := validatePlanCDNView(cfg, target, viewName, publication.plan); err != nil {
				checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, &verificationStateError{code: "REMOTE_PLAN_CDN_SCOPE_INVALID", category: verify.CategoryDrift, message: "publication plan CDN scope does not match the selected view"}))
				continue
			}
			activeAbsences := append([]pub.VerifyAbsentObject(nil), publication.plan.VerifyAbsent...)
			if len(activeAbsences) != 0 {
				aggregate, aggregateErr := loadCurrentAggregateVerificationStateForConfig(cfg, canonical, target, snapshotAbsenceInventoryCandidates(activeAbsences))
				if aggregateErr != nil {
					checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, aggregateErr))
					continue
				}
				activeAbsences = filterSupersededSnapshotAbsences(activeAbsences, aggregate)
			}
			positive := append([]pub.VerifyObject(nil), publication.plan.Verify...)
			positive = append(positive, publication.plan.Probes...)
			scoped := scopeL3Expectations(cfg, target, viewName, "", publication.generation, positive, activeAbsences, repos, values)
			for index, gap := range scoped.gaps {
				checks = append(checks, missingCheck(fmt.Sprintf("%s/selector-%06d", id, index+1), verify.LayerL3, gap.code, gap.subject, gap.message))
			}
			positive, activeAbsences = scoped.positive, scoped.absent
			headers, err := verificationHeaders(cfg, target, viewName, proToken)
			if err != nil {
				checks = append(checks, networkCredentialCheck(id, verify.LayerL3, networkFailure))
				continue
			}
			objects := make([]verify.HTTPObject, 0, len(positive))
			for index, expectation := range positive {
				requestURL := expectation.URL
				verificationSize, verificationSHA := expectation.Size, expectation.SHA256
				if viewName == "stable" && len(proToken) != 0 {
					requestURL, err = rewriteStableVerificationURL(requestURL, proToken)
					if err != nil {
						checks = append(checks, missingCheck(id, verify.LayerL3, "PRO_TOKEN_ROUTE_INVALID", target+"/stable", "stable publication plan cannot be projected onto the runtime token route"))
						objects = nil
						break
					}
					if rendered, dynamic, renderErr := runtimeTokenMirrorlistExpectation(cfg, target, viewName, requestURL, publication.generation, proToken); renderErr != nil {
						checks = append(checks, missingCheck(id, verify.LayerL3, "PRO_TOKEN_MIRRORLIST_INVALID", target+"/stable", "runtime token mirrorlist expectation cannot be derived from the committed generation"))
						objects = nil
						break
					} else if dynamic {
						verificationSize, verificationSHA = int64(len(rendered)), digestBytesCLI(rendered)
					}
				}
				objects = append(objects, verify.HTTPObject{
					Label: fmt.Sprintf("%s/%s/object-%06d", target, viewName, index+1), URL: requestURL,
					Size: verificationSize, SHA256: verificationSHA, Headers: headers,
				})
			}
			if objects == nil {
				continue
			}
			if len(objects) != 0 {
				checks = append(checks, verify.HTTPCheck{CheckID: id, Client: verificationHTTPClient, Objects: objects, MarkNetworkFailure: func() { networkFailure.Store(true) }})
			}
			absent := make([]verify.HTTPAbsentObject, 0, len(activeAbsences))
			for index, expectation := range activeAbsences {
				requestURL := expectation.URL
				if viewName == "stable" && len(proToken) != 0 {
					requestURL, err = rewriteStableVerificationURL(requestURL, proToken)
					if err != nil {
						checks = append(checks, missingCheck(id+"/absent", verify.LayerL3, "PRO_TOKEN_ROUTE_INVALID", target+"/stable", "snapshot deletion expectation cannot be projected onto the runtime token route"))
						absent = nil
						break
					}
				}
				absent = append(absent, verify.HTTPAbsentObject{Label: fmt.Sprintf("%s/%s/absent-%06d", target, viewName, index+1), URL: requestURL, Headers: headers})
			}
			if len(absent) != 0 {
				checks = append(checks, verify.HTTPAbsenceCheck{CheckID: id + "/absent", Client: verificationHTTPClient, Objects: absent, MarkNetworkFailure: func() { networkFailure.Store(true) }})
			}
			if len(objects) == 0 && len(absent) == 0 && len(scoped.gaps) == 0 {
				checks = append(checks, missingCheck(id, verify.LayerL3, "REMOTE_PLAN_CDN_PROBE_MISSING", target+"/"+viewName, "committed publication plan has no positive or negative CDN expectation"))
			}
		}
	}
	if len(checks) == 0 {
		checks = append(checks, missingCheck("cdn/coverage", verify.LayerL3, "CDN_TARGET_COVERAGE_MISSING", "L3", "no configured target can execute an L3 probe"))
	}
	return checks, nil
}

func buildSnapshotL3Checks(cfg *config.Config, canonical *state.Store, repos []config.Repo, snapshotID string, values commonFlags, selectedTargets []string, proToken []byte, networkFailure *atomic.Bool) ([]verify.Check, error) {
	var checks []verify.Check
	for _, target := range verifyTargetNames(cfg, selectedTargets) {
		publication, stateErr := loadCommittedVerificationStateForConfig(cfg, canonical, target, "snapshot", snapshotID)
		id := "cdn/" + target + "/snapshot/" + snapshotID
		if stateErr != nil {
			checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, stateErr))
			continue
		}
		configSHA, err := publicationConfigSHA256ForGeneration(cfg, publication.generation)
		if err != nil {
			return nil, err
		}
		if publication.generation.ConfigSHA256 != configSHA {
			checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, &verificationStateError{code: "REMOTE_CONFIG_DRIFT", category: verify.CategoryDrift, message: "current configuration differs from the committed snapshot generation"}))
			continue
		}
		keyMatches, err := generationRepositoryTrustMatches(cfg, publication.generation)
		if err != nil {
			return nil, err
		}
		if !keyMatches {
			checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, &verificationStateError{code: "REMOTE_REPOSITORY_KEY_DRIFT", category: verify.CategoryDrift, message: "current repository public key differs from the committed generation"}))
			continue
		}
		if publication.generation.IntentView != "snapshot" || publication.generation.IntentSnapshot != snapshotID {
			checks = append(checks, missingCheck(id, verify.LayerL3, "REMOTE_PLAN_SNAPSHOT_COVERAGE_MISSING", target+"/"+snapshotID, "committed publication plan belongs to another snapshot"))
			continue
		}
		if err := validatePlanCDNSnapshot(cfg, target, snapshotID, publication.plan); err != nil {
			checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, &verificationStateError{code: "REMOTE_PLAN_CDN_SCOPE_INVALID", category: verify.CategoryDrift, message: "publication plan CDN scope does not match the selected snapshot"}))
			continue
		}
		activeAbsences := append([]pub.VerifyAbsentObject(nil), publication.plan.VerifyAbsent...)
		if len(activeAbsences) != 0 {
			aggregate, aggregateErr := loadCurrentAggregateVerificationStateForConfig(cfg, canonical, target, snapshotAbsenceInventoryCandidates(activeAbsences))
			if aggregateErr != nil {
				checks = append(checks, verificationStateCheck(id, verify.LayerL3, target, aggregateErr))
				continue
			}
			activeAbsences = filterSupersededSnapshotAbsences(activeAbsences, aggregate)
		}
		positive := append([]pub.VerifyObject(nil), publication.plan.Verify...)
		positive = append(positive, publication.plan.Probes...)
		scoped := scopeL3Expectations(cfg, target, "snapshot", snapshotID, publication.generation, positive, activeAbsences, repos, values)
		for index, gap := range scoped.gaps {
			checks = append(checks, missingCheck(fmt.Sprintf("%s/selector-%06d", id, index+1), verify.LayerL3, gap.code, gap.subject, gap.message))
		}
		positive, activeAbsences = scoped.positive, scoped.absent
		headers, err := verificationHeaders(cfg, target, "stable", proToken)
		if err != nil {
			checks = append(checks, networkCredentialCheck(id, verify.LayerL3, networkFailure))
			continue
		}
		objects := make([]verify.HTTPObject, 0, len(positive))
		for index, expectation := range positive {
			requestURL := expectation.URL
			if len(proToken) != 0 {
				requestURL, err = rewriteStableVerificationURL(requestURL, proToken)
				if err != nil {
					objects = nil
					checks = append(checks, missingCheck(id, verify.LayerL3, "PRO_TOKEN_ROUTE_INVALID", target+"/"+snapshotID, "snapshot publication plan cannot be projected onto the runtime token route"))
					break
				}
			}
			objects = append(objects, verify.HTTPObject{
				Label: fmt.Sprintf("%s/snapshot/%s/object-%06d", target, snapshotID, index+1), URL: requestURL,
				Size: expectation.Size, SHA256: expectation.SHA256, Headers: headers,
			})
		}
		if objects == nil {
			continue
		}
		if len(objects) != 0 {
			checks = append(checks, verify.HTTPCheck{CheckID: id, Client: verificationHTTPClient, Objects: objects, MarkNetworkFailure: func() { networkFailure.Store(true) }})
		}
		absent := make([]verify.HTTPAbsentObject, 0, len(activeAbsences))
		for index, expectation := range activeAbsences {
			requestURL := expectation.URL
			if len(proToken) != 0 {
				requestURL, err = rewriteStableVerificationURL(requestURL, proToken)
				if err != nil {
					checks = append(checks, missingCheck(id+"/absent", verify.LayerL3, "PRO_TOKEN_ROUTE_INVALID", target+"/"+snapshotID, "snapshot deletion expectation cannot be projected onto the runtime token route"))
					absent = nil
					break
				}
			}
			absent = append(absent, verify.HTTPAbsentObject{Label: fmt.Sprintf("%s/snapshot/%s/absent-%06d", target, snapshotID, index+1), URL: requestURL, Headers: headers})
		}
		if len(absent) != 0 {
			checks = append(checks, verify.HTTPAbsenceCheck{CheckID: id + "/absent", Client: verificationHTTPClient, Objects: absent, MarkNetworkFailure: func() { networkFailure.Store(true) }})
		}
		if len(objects) == 0 && len(absent) == 0 && len(scoped.gaps) == 0 {
			checks = append(checks, missingCheck(id, verify.LayerL3, "REMOTE_PLAN_CDN_PROBE_MISSING", target+"/"+snapshotID, "committed snapshot plan has no positive or negative CDN expectation"))
		}
	}
	if len(checks) == 0 {
		checks = append(checks, missingCheck("cdn/snapshot/coverage", verify.LayerL3, "CDN_TARGET_COVERAGE_MISSING", snapshotID, "no configured target can execute a snapshot L3 probe"))
	}
	return checks, nil
}

func buildL4Checks(cfg *config.Config, canonical *state.Store, repos []config.Repo, viewsToCheck []string, values commonFlags, selectedTargets []string, publicKeyFile string, proToken []byte, tempDir string, networkFailure *atomic.Bool) ([]verify.Check, error) {
	var packageRepos []config.Repo
	for _, repo := range repos {
		if repo.Type == "apt" || repo.Type == "yum" {
			packageRepos = append(packageRepos, repo)
		}
	}
	if len(packageRepos) == 0 {
		return []verify.Check{missingCheck("client/coverage", verify.LayerL4, "CLIENT_REPOSITORY_COVERAGE_MISSING", "L4", "selectors matched no APT or YUM repository")}, nil
	}
	key, err := loadRepositoryPublicKey(cfg, publicKeyFile)
	if err != nil {
		return nil, err
	}
	aptVerifier, err := verify.NewAPTVerifier(bytes.NewReader(key))
	if err != nil {
		return nil, errors.New("invalid repository OpenPGP public key")
	}
	verificationTime := time.Now().UTC()
	yumVerifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(key), verificationTime)
	if err != nil {
		return nil, errors.New("invalid repository OpenPGP public key")
	}
	targets := verifyTargetNames(cfg, selectedTargets)
	var checks []verify.Check
	rpmPackageKeyrings := make(map[string]openpgp.KeyRing)
	for _, target := range targets {
		targetPackageRepos := reposPublishingToTarget(packageRepos, target)
		if len(targetPackageRepos) == 0 {
			continue
		}
		// Compatibility channels inherit the source owner's target affinity. A
		// sibling cloud must never probe or require a projection it cannot publish.
		compatibilityProjections, err := selectedLatestYUMCompatibilityForTarget(cfg, packageRepos, target, viewsToCheck, values)
		if err != nil {
			return nil, err
		}
		for _, viewName := range viewsToCheck {
			leaves := selectedVerificationViewLeaves(cfg, targetPackageRepos, target, viewName, values)
			viewCompatibility := compatibilityProjections
			if viewName != "latest" {
				viewCompatibility = nil
			}
			if len(leaves) == 0 && len(viewCompatibility) == 0 {
				continue
			}
			publication, stateErr := loadCommittedVerificationStateForConfig(cfg, canonical, target, viewName, "")
			prefix := "client/" + target + "/" + viewName
			if stateErr != nil {
				checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, stateErr))
				continue
			}
			configSHA, err := publicationConfigSHA256ForGeneration(cfg, publication.generation)
			if err != nil {
				return nil, err
			}
			if publication.generation.ConfigSHA256 != configSHA {
				checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, &verificationStateError{code: "REMOTE_CONFIG_DRIFT", category: verify.CategoryDrift, message: "current configuration differs from the committed publication generation"}))
				continue
			}
			keyMatches, err := generationRepositoryTrustMatches(cfg, publication.generation)
			if err != nil {
				return nil, err
			}
			if !keyMatches {
				checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, &verificationStateError{code: "REMOTE_REPOSITORY_KEY_DRIFT", category: verify.CategoryDrift, message: "current repository public key differs from the committed generation"}))
				continue
			}
			if publication.generation.IntentView != viewName {
				checks = append(checks, missingCheck(prefix, verify.LayerL4, "REMOTE_PLAN_VIEW_COVERAGE_MISSING", target+"/"+viewName, "last committed publication plan belongs to another view"))
				continue
			}
			if err := validatePlanCDNView(cfg, target, viewName, publication.plan); err != nil {
				checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, &verificationStateError{code: "REMOTE_PLAN_CDN_SCOPE_INVALID", category: verify.CategoryDrift, message: "publication plan CDN scope does not match the selected view"}))
				continue
			}
			headers, err := verificationHeaders(cfg, target, viewName, proToken)
			if err != nil {
				checks = append(checks, networkCredentialCheck(prefix, verify.LayerL4, networkFailure))
				continue
			}
			for _, leaf := range leaves {
				id := prefix + "/" + leaf.repo.ID + "/" + leaf.os + "/" + leaf.arch
				if !generationHasLeaf(publication.generation, viewName, leaf) {
					checks = append(checks, missingCheck(id, verify.LayerL4, "REMOTE_REF_COVERAGE_MISSING", leaf.repo.ID+"/"+leaf.os+"/"+leaf.arch, "committed generation does not cover the selected repository leaf"))
					continue
				}
				baseURL := verificationCDNBase(cfg, target, viewName)
				credentialPrefix, err := protocolViewPrefix(viewName, proToken)
				if err != nil {
					checks = append(checks, missingCheck(prefix, verify.LayerL4, "PRO_TOKEN_ROUTE_INVALID", target+"/stable", "runtime Pro token cannot form a safe repository route"))
					continue
				}
				switch leaf.repo.Type {
				case "apt":
					repositoryPath := path.Join(credentialPrefix, leaf.repo.Path)
					suiteComponents := leaf.repo.APT.ComponentsForSuite(leaf.os)
					probe := exactAPTRepositoryProbe(verify.APTProtocolProbe{
						Client: verificationHTTPClient, CDNBaseURL: baseURL, RepositoryPath: repositoryPath,
						Suite: leaf.os, Architecture: leaf.arch, Headers: headers, Verifier: aptVerifier,
						VerifyAt: time.Now().UTC(), TempDir: tempDir, ChunkEntries: values.chunk,
					}, suiteComponents)
					checks = append(checks, verify.ClientCheck{CheckID: id, Probe: probe, MarkNetworkFailure: func() { networkFailure.Store(true) }})
				case "yum":
					packageKeyring := rpmPackageKeyrings[leaf.repo.ID]
					if packageKeyring == nil {
						loaded, _, loadErr := loadRPMPackageKeyring(cfg.Path, leaf.repo.YUM.PackageKeyring)
						if loadErr != nil || loaded == nil {
							return nil, errors.Join(loadErr, fmt.Errorf("repo %s has no usable RPM package keyring", leaf.repo.ID))
						}
						packageKeyring = loaded
						rpmPackageKeyrings[leaf.repo.ID] = loaded
					}
					channel, channelExists := generationChannel(publication.generation, viewName, leaf)
					if !channelExists {
						checks = append(checks, missingCheck(id, verify.LayerL4, "YUM_CHANNEL_COVERAGE_MISSING", leaf.repo.ID+"/"+leaf.os+"/"+leaf.arch, "committed generation has no mirrorlist channel for the selected YUM leaf"))
						continue
					}
					mirrorlist := path.Join(credentialPrefix, "_sow/v1/mirrorlist", viewName, leaf.repo.ID, leaf.os, leaf.arch+".txt")
					compression := yumrepo.CompressionZstd
					if leaf.repo.YUM.Compression == "gzip" {
						compression = yumrepo.CompressionGzip
					}
					probe := verify.YUMProtocolProbe{
						Client: verificationHTTPClient, CDNBaseURL: baseURL, MirrorlistPath: mirrorlist,
						ExpectedGenerationURL: expectedYUMGenerationURL(baseURL, credentialPrefix, channel), Headers: headers,
						Architecture: leaf.arch, Compression: compression, Verifier: yumVerifier,
						PackageKeyring: packageKeyring, VerifyAt: verificationTime, TempDir: tempDir, ChunkEntries: values.chunk,
					}
					checks = append(checks, verify.ClientCheck{CheckID: id, Probe: probe, MarkNetworkFailure: func() { networkFailure.Store(true) }})
				}
			}
			for _, projection := range viewCompatibility {
				id := prefix + "/compatibility/" + projection.ID
				identity, exists := compatibilityStateAtGeneration(publication.generation, projection.ID)
				if !exists {
					checks = append(checks, missingCheck(id, verify.LayerL4, "YUM_COMPATIBILITY_IDENTITY_COVERAGE_MISSING", projection.ID, "committed latest generation has no frozen compatibility identity"))
					continue
				}
				channel, exists := compatibilityChannel(publication.generation, identity.ChannelRemoteKey)
				if !exists || channel.View != "latest" || channel.Repo != projection.ID || channel.OS != "cross-el" || channel.Arch != projection.Source.Arch || channel.LegacyRoot != projection.Root {
					checks = append(checks, missingCheck(id, verify.LayerL4, "YUM_COMPATIBILITY_CHANNEL_COVERAGE_MISSING", projection.ID, "committed latest generation has no exact independent cross-EL channel"))
					continue
				}
				packageKeyring, err := loadFrozenCompatibilityPackageKeyring(canonical, identity)
				if err != nil {
					checks = append(checks, verificationStateCheck(id, verify.LayerL4, target, &verificationStateError{code: "YUM_COMPATIBILITY_PACKAGE_TRUST_DRIFT", category: verify.CategoryIntegrity, message: err.Error()}))
					continue
				}
				checks = append(checks, buildCompatibilityL4Checks(cfg, target, id, projection, channel, headers, yumVerifier, packageKeyring, verificationTime, tempDir, values.chunk, networkFailure)...)
			}
		}
	}
	if len(checks) == 0 {
		checks = append(checks, missingCheck("client/coverage", verify.LayerL4, "CLIENT_TARGET_COVERAGE_MISSING", "L4", "no configured target can execute an L4 probe"))
	}
	return checks, nil
}

// buildCompatibilityL4Checks deliberately emits two independent probes. The
// mirrorlist/generation check proves the atomic channel contract while the raw
// check preserves the frozen legacy URL. Sharing the frozen metadata verifier
// and S1 package keyring does not let either route substitute for the other.
func buildCompatibilityL4Checks(cfg *config.Config, target, id string, projection config.YUMCompatibilityProjection, channel pub.ChannelState, headers http.Header, verifier yumrepo.DetachedVerifier, packageKeyring openpgp.KeyRing, verificationTime time.Time, tempDir string, chunkEntries int, networkFailure *atomic.Bool) []verify.Check {
	baseURL := verificationCDNBase(cfg, target, "latest")
	markNetworkFailure := func() {
		if networkFailure != nil {
			networkFailure.Store(true)
		}
	}
	generationProbe := verify.YUMProtocolProbe{
		Client: verificationHTTPClient, CDNBaseURL: baseURL,
		MirrorlistPath:        path.Join("_sow/v1/mirrorlist", "latest", projection.ID, "cross-el", projection.Source.Arch+".txt"),
		ExpectedGenerationURL: expectedYUMGenerationURL(baseURL, "", channel), Headers: headers,
		Architecture: projection.Source.Arch, Compression: yumrepo.CompressionGzip, Verifier: verifier,
		PackageKeyring: packageKeyring, VerifyAt: verificationTime, TempDir: tempDir, ChunkEntries: chunkEntries,
	}
	rawProbe := verify.YUMProtocolProbe{
		Client: verificationHTTPClient, CDNBaseURL: baseURL, RepositoryPath: projection.Root, Headers: headers,
		Architecture: projection.Source.Arch, Compression: yumrepo.CompressionGzip, Verifier: verifier,
		PackageKeyring: packageKeyring, VerifyAt: verificationTime, TempDir: tempDir, ChunkEntries: chunkEntries,
	}
	return []verify.Check{
		verify.ClientCheck{CheckID: id + "/generation", Probe: generationProbe, MarkNetworkFailure: markNetworkFailure},
		verify.ClientCheck{CheckID: id + "/raw", Probe: rawProbe, MarkNetworkFailure: markNetworkFailure},
	}
}

// loadFrozenCompatibilityPackageKeyring opens the S1 trust bytes at the exact
// preservation commit named by the publication identity. It never follows the
// owner's mutable package_keyring config path, so key rotation cannot silently
// reinterpret an already published cross-EL package set.
func loadFrozenCompatibilityPackageKeyring(canonical *state.Store, identity pub.CompatibilityState) (openpgp.KeyRing, error) {
	freezeCommit := plumbing.NewHash(identity.FreezeCommit)
	if canonical == nil || freezeCommit.IsZero() {
		return nil, errors.New("frozen compatibility package trust commit is unavailable")
	}
	trustPath, err := state.YUMCompatibilityPackageTrustPath(identity.ID)
	if err != nil {
		return nil, err
	}
	body, exists, err := readCanonicalBytesAt(canonical, freezeCommit, trustPath, maxSecretBytes)
	if err != nil || !exists || int64(len(body)) != identity.PackageTrustSize || digestBytesCLI(body) != identity.PackageTrustSHA256 {
		return nil, errors.Join(err, fmt.Errorf("compatibility %s frozen package trust bytes differ from publication identity", identity.ID))
	}
	blob, exists, err := canonical.BlobIdentityAt(freezeCommit, trustPath)
	if err != nil || !exists || blob.Hash.String() != identity.PackageTrustGit || blob.Size != identity.PackageTrustSize {
		return nil, errors.Join(err, fmt.Errorf("compatibility %s frozen package trust Git identity differs from publication identity", identity.ID))
	}
	keyring, err := yumrepo.ParseRPMPackageKeyring(body)
	if err != nil || keyring == nil {
		return nil, errors.Join(err, fmt.Errorf("compatibility %s frozen package trust contains no usable key", identity.ID))
	}
	return keyring, nil
}

func buildSnapshotL4Checks(cfg *config.Config, canonical *state.Store, repos []config.Repo, snapshotID string, values commonFlags, selectedTargets []string, publicKeyFile string, proToken []byte, tempDir string, networkFailure *atomic.Bool) ([]verify.Check, error) {
	var packageRepos []config.Repo
	for _, repo := range repos {
		if repo.Type == "apt" || repo.Type == "yum" {
			packageRepos = append(packageRepos, repo)
		}
	}
	leaves, err := selectedSnapshotLeaves(cfg, repos, values, snapshotID)
	if err != nil {
		return nil, err
	}
	var packageLeaves []viewLeaf
	for _, leaf := range leaves {
		if leaf.repo.Type == "apt" || leaf.repo.Type == "yum" {
			packageLeaves = append(packageLeaves, leaf)
		}
	}
	if len(packageLeaves) == 0 {
		return []verify.Check{missingCheck("client/snapshot/"+snapshotID+"/coverage", verify.LayerL4, "CLIENT_REPOSITORY_COVERAGE_MISSING", snapshotID, "selectors matched no APT or YUM repository for this snapshot suite")}, nil
	}
	key, err := loadRepositoryPublicKey(cfg, publicKeyFile)
	if err != nil {
		return nil, err
	}
	aptVerifier, err := verify.NewAPTVerifier(bytes.NewReader(key))
	if err != nil {
		return nil, errors.New("invalid repository OpenPGP public key")
	}
	verificationTime := time.Now().UTC()
	yumVerifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(key), verificationTime)
	if err != nil {
		return nil, errors.New("invalid repository OpenPGP public key")
	}
	var checks []verify.Check
	rpmPackageKeyrings := make(map[string]openpgp.KeyRing)
	for _, target := range verifyTargetNames(cfg, selectedTargets) {
		targetLeaves, err := selectedVerificationSnapshotLeaves(cfg, packageRepos, target, snapshotID, values)
		if err != nil {
			return nil, err
		}
		if len(targetLeaves) == 0 {
			continue
		}
		publication, stateErr := loadCommittedVerificationStateForConfig(cfg, canonical, target, "snapshot", snapshotID)
		prefix := "client/" + target + "/snapshot/" + snapshotID
		if stateErr != nil {
			checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, stateErr))
			continue
		}
		configSHA, err := publicationConfigSHA256ForGeneration(cfg, publication.generation)
		if err != nil {
			return nil, err
		}
		if publication.generation.ConfigSHA256 != configSHA {
			checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, &verificationStateError{code: "REMOTE_CONFIG_DRIFT", category: verify.CategoryDrift, message: "current configuration differs from the committed snapshot generation"}))
			continue
		}
		keyMatches, err := generationRepositoryTrustMatches(cfg, publication.generation)
		if err != nil {
			return nil, err
		}
		if !keyMatches {
			checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, &verificationStateError{code: "REMOTE_REPOSITORY_KEY_DRIFT", category: verify.CategoryDrift, message: "current repository public key differs from the committed generation"}))
			continue
		}
		if publication.generation.IntentView != "snapshot" || publication.generation.IntentSnapshot != snapshotID {
			checks = append(checks, missingCheck(prefix, verify.LayerL4, "REMOTE_PLAN_SNAPSHOT_COVERAGE_MISSING", target+"/"+snapshotID, "committed publication plan belongs to another snapshot"))
			continue
		}
		if err := validatePlanCDNSnapshot(cfg, target, snapshotID, publication.plan); err != nil {
			checks = append(checks, verificationStateCheck(prefix, verify.LayerL4, target, &verificationStateError{code: "REMOTE_PLAN_CDN_SCOPE_INVALID", category: verify.CategoryDrift, message: "publication plan CDN scope does not match the selected snapshot"}))
			continue
		}
		headers, err := verificationHeaders(cfg, target, "stable", proToken)
		if err != nil {
			checks = append(checks, networkCredentialCheck(prefix, verify.LayerL4, networkFailure))
			continue
		}
		credentialPrefix, err := protocolViewPrefix("stable", proToken)
		if err != nil {
			checks = append(checks, missingCheck(prefix, verify.LayerL4, "PRO_TOKEN_ROUTE_INVALID", target+"/"+snapshotID, "runtime Pro token cannot form a safe snapshot route"))
			continue
		}
		baseURL := verificationCDNBase(cfg, target, "stable")
		for _, leaf := range targetLeaves {
			id := prefix + "/" + leaf.repo.ID + "/" + leaf.os + "/" + leaf.arch
			if !generationHasSnapshotLeaf(publication.generation, snapshotID, leaf) {
				checks = append(checks, missingCheck(id, verify.LayerL4, "REMOTE_SNAPSHOT_REF_COVERAGE_MISSING", leaf.repo.ID+"/"+leaf.os+"/"+leaf.arch, "committed generation does not cover the selected snapshot leaf"))
				continue
			}
			switch leaf.repo.Type {
			case "apt":
				repositoryPath := path.Join(credentialPrefix, "_sow/v1/snapshots", snapshotID, "apt", leaf.repo.Path)
				suiteComponents := leaf.repo.APT.ComponentsForSuite(leaf.os)
				probe := exactAPTRepositoryProbe(verify.APTProtocolProbe{
					Client: verificationHTTPClient, CDNBaseURL: baseURL, RepositoryPath: repositoryPath,
					Suite: snapshotID, Architecture: leaf.arch, Headers: headers, Verifier: aptVerifier,
					VerifyAt: time.Now().UTC(), TempDir: tempDir, ChunkEntries: values.chunk,
				}, suiteComponents)
				checks = append(checks, verify.ClientCheck{CheckID: id, Probe: probe, MarkNetworkFailure: func() { networkFailure.Store(true) }})
			case "yum":
				packageKeyring := rpmPackageKeyrings[leaf.repo.ID]
				if packageKeyring == nil {
					loaded, _, loadErr := loadRPMPackageKeyring(cfg.Path, leaf.repo.YUM.PackageKeyring)
					if loadErr != nil || loaded == nil {
						return nil, errors.Join(loadErr, fmt.Errorf("repo %s has no usable RPM package keyring", leaf.repo.ID))
					}
					packageKeyring = loaded
					rpmPackageKeyrings[leaf.repo.ID] = loaded
				}
				effective, pathErr := leaf.repo.PathForArch(leaf.arch)
				if pathErr != nil {
					return nil, pathErr
				}
				compression := yumrepo.CompressionZstd
				if leaf.repo.YUM.Compression == "gzip" {
					compression = yumrepo.CompressionGzip
				}
				probe := verify.YUMProtocolProbe{
					Client: verificationHTTPClient, CDNBaseURL: baseURL,
					RepositoryPath: path.Join(credentialPrefix, "_sow/v1/snapshots", snapshotID, "yum", effective),
					Headers:        headers, Architecture: leaf.arch, Compression: compression,
					Verifier: yumVerifier, PackageKeyring: packageKeyring, VerifyAt: verificationTime,
					TempDir: tempDir, ChunkEntries: values.chunk,
				}
				checks = append(checks, verify.ClientCheck{CheckID: id, Probe: probe, MarkNetworkFailure: func() { networkFailure.Store(true) }})
			}
		}
	}
	if len(checks) == 0 {
		checks = append(checks, missingCheck("client/snapshot/coverage", verify.LayerL4, "CLIENT_TARGET_COVERAGE_MISSING", snapshotID, "no configured target can execute a snapshot L4 probe"))
	}
	return checks, nil
}

// exactAPTRepositoryProbe binds every component fallback probe to the same
// complete suite contract. This is stronger than proving one configured
// component is installable: a signed Release that also exposes an unauthorized
// stable/testing sibling component must fail L4 integrity verification.
func exactAPTRepositoryProbe(base verify.APTProtocolProbe, suiteComponents []string) verify.APTRepositoryProbe {
	exact := append([]string(nil), suiteComponents...)
	components := make([]verify.APTProtocolProbe, 0, len(exact))
	for _, component := range exact {
		probe := base
		probe.Component = component
		probe.ExpectedComponents = append([]string(nil), exact...)
		components = append(components, probe)
	}
	return verify.APTRepositoryProbe{Components: components}
}

func verificationStateCheck(id string, layer verify.Layer, target string, err error) verify.Check {
	code, category, message := "REMOTE_VERIFICATION_STATE_INVALID", verify.CategoryIntegrity, "canonical remote verification state is invalid"
	var stateErr *verificationStateError
	if errors.As(err, &stateErr) {
		code, category, message = stateErr.code, stateErr.category, stateErr.message
	}
	return verify.CheckFunc{CheckID: id, CheckLayer: layer, Run: func(_ context.Context, recorder *verify.Recorder) error {
		recorder.Add(verify.Finding{Layer: layer, Severity: verify.SeverityCritical, Category: category, Code: code, Subject: target, Message: message})
		return nil
	}}
}

func networkCredentialCheck(id string, layer verify.Layer, networkFailure *atomic.Bool) verify.Check {
	return verify.CheckFunc{CheckID: id, CheckLayer: layer, Run: func(context.Context, *verify.Recorder) error {
		networkFailure.Store(true)
		return errors.New("CDN verification credential is unavailable")
	}}
}

func verifyTargetNames(cfg *config.Config, selected []string) []string {
	if len(selected) != 0 {
		return uniqueSorted(selected)
	}
	result := make([]string, 0, len(cfg.Targets))
	for target := range cfg.Targets {
		result = append(result, target)
	}
	sort.Strings(result)
	return result
}

func validatePlanCDNView(cfg *config.Config, target, viewName string, plan pub.Plan) error {
	wanted := strings.TrimSuffix(verificationCDNBase(cfg, target, viewName), "/") + "/"
	if plan.CDNBaseURL != wanted {
		return errors.New("plan CDN base differs")
	}
	positive := append([]pub.VerifyObject(nil), plan.Verify...)
	positive = append(positive, plan.Probes...)
	for _, expectation := range positive {
		u, err := url.Parse(expectation.URL)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
			return errors.New("plan verification URL is unsafe")
		}
		basic := strings.Contains(u.Path, "/pro/v1/basic/")
		if viewName == "stable" && !basic || viewName != "stable" && basic {
			return errors.New("plan verification credential route differs")
		}
	}
	for _, expectation := range plan.VerifyAbsent {
		u, err := url.Parse(expectation.URL)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path {
			return errors.New("plan absence verification URL is unsafe")
		}
		basic := strings.Contains(u.Path, "/pro/v1/basic/")
		if viewName == "stable" && !basic || viewName != "stable" && basic {
			return errors.New("plan absence verification credential route differs")
		}
	}
	return nil
}

func validatePlanCDNSnapshot(cfg *config.Config, target, snapshotID string, plan pub.Plan) error {
	if err := pub.ValidatePublicationIntent("snapshot", snapshotID); err != nil {
		return err
	}
	base, err := url.Parse(strings.TrimSuffix(verificationCDNBase(cfg, target, "stable"), "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return errors.New("snapshot CDN base is invalid")
	}
	if plan.CDNBaseURL != base.String()+"/" {
		return errors.New("plan CDN base differs")
	}
	wantedPrefix := path.Join("/pro/v1/basic/_sow/v1/snapshots", snapshotID) + "/"
	positive := append([]pub.VerifyObject(nil), plan.Verify...)
	positive = append(positive, plan.Probes...)
	for _, expectation := range positive {
		u, err := url.Parse(expectation.URL)
		if err != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path || !strings.HasPrefix(u.Path, wantedPrefix) {
			return errors.New("snapshot verification URL is outside its exact Basic route")
		}
	}
	for _, expectation := range plan.VerifyAbsent {
		u, err := url.Parse(expectation.URL)
		if err != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path {
			return errors.New("snapshot absence verification URL is unsafe")
		}
		prefix := path.Join("/pro/v1/basic/_sow/v1/snapshots") + "/"
		if !strings.HasPrefix(u.Path, prefix) || !strings.HasSuffix(u.Path, "/_route.json") {
			return errors.New("snapshot absence verification URL is outside snapshot routes")
		}
		remainder := strings.TrimSuffix(strings.TrimPrefix(u.Path, prefix), "/_route.json")
		if strings.Contains(remainder, "/") || pub.ValidatePublicationIntent("snapshot", remainder) != nil {
			return errors.New("snapshot absence verification URL has an invalid snapshot ID")
		}
	}
	return nil
}

func verificationHeaders(cfg *config.Config, target, viewName string, proToken []byte) (http.Header, error) {
	headers := make(http.Header)
	if viewName != "stable" {
		return headers, nil
	}
	if len(proToken) != 0 {
		if !proVerificationTokenPattern.Match(proToken) {
			return nil, errors.New("runtime Pro token is not a safe credential segment")
		}
		return headers, nil
	}
	configured := cfg.Targets[target]
	raw, err := resolveSecret(configured.CDN.Credential, "", false)
	if err != nil {
		return nil, errors.New("resolve CDN Basic verification credential")
	}
	defer clearSecret(raw)
	username, password := "", ""
	if target == "cf" {
		var secret cloudflareCDNSecret
		if err := decodeSecretJSON(raw, &secret); err != nil {
			return nil, errors.New("decode CDN verification credential")
		}
		username, password = secret.BasicUser, secret.BasicPassword
	} else {
		var secret tencentCDNSecret
		if err := decodeSecretJSON(raw, &secret); err != nil {
			return nil, errors.New("decode CDN verification credential")
		}
		username, password = secret.BasicUser, secret.BasicPassword
	}
	if _, err := basicVerificationCredentials(username, password, true); err != nil {
		return nil, errors.New("CDN Basic verification credential is incomplete")
	}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	return headers, nil
}

func verificationCDNBase(cfg *config.Config, target, viewName string) string {
	if viewName == "beta" {
		return cfg.Targets[target].CDN.BetaBaseURL
	}
	return cfg.Targets[target].CDN.BaseURL
}

func protocolViewPrefix(viewName string, proToken []byte) (string, error) {
	if viewName != "stable" {
		return "", nil
	}
	if len(proToken) == 0 {
		return "pro/v1/basic", nil
	}
	if !proVerificationTokenPattern.Match(proToken) {
		return "", errors.New("runtime Pro token is not a safe credential segment")
	}
	return "pro/v1/" + string(proToken), nil
}

func loadProVerificationToken(filename string, viewsToCheck []string) ([]byte, error) {
	return loadProVerificationTokenForIntent(filename, viewsToCheck, "")
}

func loadProVerificationTokenForIntent(filename string, viewsToCheck []string, snapshotID string) ([]byte, error) {
	if filename == "" {
		return nil, nil
	}
	if snapshotID == "" && !containsStringValueCLI(viewsToCheck, "stable") {
		return nil, errors.New("--pro-token-file requires --view stable or --snapshot")
	}
	if snapshotID != "" {
		if err := pub.ValidatePublicationIntent("snapshot", snapshotID); err != nil {
			return nil, errors.New("--pro-token-file requires a valid snapshot intent")
		}
	}
	token, err := readSecretFile(filename)
	if err != nil {
		return nil, errors.New("read runtime Pro token file")
	}
	if len(token) > 0 && token[len(token)-1] == '\n' {
		token = token[:len(token)-1]
		if len(token) > 0 && token[len(token)-1] == '\r' {
			token = token[:len(token)-1]
		}
	}
	if !proVerificationTokenPattern.Match(token) {
		clearSecret(token)
		return nil, errors.New("runtime Pro token must be a 22-256 character base64url path segment")
	}
	return token, nil
}

func rewriteStableVerificationURL(raw string, proToken []byte) (string, error) {
	if !proVerificationTokenPattern.Match(proToken) {
		return "", errors.New("runtime Pro token is not a safe credential segment")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path {
		return "", errors.New("stable verification URL is not canonical")
	}
	segments := strings.Split(u.Path, "/")
	credentialIndex := -1
	for index := 0; index+2 < len(segments); index++ {
		if segments[index] == "pro" && segments[index+1] == "v1" && segments[index+2] == "basic" {
			if credentialIndex >= 0 {
				return "", errors.New("stable verification URL has multiple credential routes")
			}
			credentialIndex = index + 2
		}
	}
	if credentialIndex < 0 {
		return "", errors.New("stable verification URL lacks the Basic projection route")
	}
	segments[credentialIndex] = string(proToken)
	u.Path = strings.Join(segments, "/")
	u.RawPath = ""
	return u.String(), nil
}

func runtimeTokenMirrorlistExpectation(cfg *config.Config, target, viewName, requestURL string, generation pub.TargetGeneration, proToken []byte) ([]byte, bool, error) {
	if viewName != "stable" || !proVerificationTokenPattern.Match(proToken) {
		return nil, false, nil
	}
	u, err := url.Parse(requestURL)
	if err != nil {
		return nil, false, errors.New("runtime mirrorlist URL is invalid")
	}
	segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	marker := -1
	for index := 0; index+2 < len(segments); index++ {
		if segments[index] == "_sow" && segments[index+1] == "v1" && segments[index+2] == "mirrorlist" {
			marker = index
			break
		}
	}
	if marker < 0 {
		return nil, false, nil
	}
	if len(segments) != marker+7 || segments[marker+3] != viewName || !strings.HasSuffix(segments[marker+6], ".txt") {
		return nil, true, errors.New("runtime mirrorlist path is not canonical")
	}
	repo, osName, arch := segments[marker+4], segments[marker+5], strings.TrimSuffix(segments[marker+6], ".txt")
	for _, channel := range generation.Channels {
		if channel.View != viewName || channel.Repo != repo || channel.OS != osName || channel.Arch != arch {
			continue
		}
		base := strings.TrimSuffix(verificationCDNBase(cfg, target, viewName), "/")
		body := fmt.Sprintf("%s/pro/v1/%s/_sow/v1/g/%020d/%s/\n", base, proToken, channel.Generation, channel.LegacyRoot)
		return []byte(body), true, nil
	}
	return nil, true, errors.New("runtime mirrorlist has no committed channel")
}

func containsStringValueCLI(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func generationHasLeaf(generation pub.TargetGeneration, viewName string, leaf viewLeaf) bool {
	wanted, err := state.ViewRef(viewName, leaf.repo.ID, leaf.os, leaf.arch)
	if err != nil {
		return false
	}
	for _, ref := range generation.Refs {
		if ref.Name == wanted.String() {
			return true
		}
	}
	return false
}

func generationChannel(generation pub.TargetGeneration, viewName string, leaf viewLeaf) (pub.ChannelState, bool) {
	for _, channel := range generation.Channels {
		if channel.View == viewName && channel.Repo == leaf.repo.ID && channel.OS == leaf.os && channel.Arch == leaf.arch {
			return channel, true
		}
	}
	return pub.ChannelState{}, false
}

func expectedYUMGenerationURL(baseURL, credentialPrefix string, channel pub.ChannelState) string {
	root := path.Join(credentialPrefix, "_sow/v1/g", fmt.Sprintf("%020d", channel.Generation), channel.LegacyRoot)
	return strings.TrimSuffix(baseURL, "/") + "/" + root + "/"
}

func generationHasSnapshotLeaf(generation pub.TargetGeneration, snapshotID string, leaf viewLeaf) bool {
	wanted, err := state.SnapshotRef(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
	if err != nil {
		return false
	}
	for _, ref := range generation.Refs {
		if ref.Name == wanted.String() {
			return true
		}
	}
	return false
}
