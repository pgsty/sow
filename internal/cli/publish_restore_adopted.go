package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

// historicalPublicationClosure is the complete canonical proof of one
// successful target publication as it existed at one state commit. A plan is
// useful as restore provenance only when every member of this closure agrees.
type historicalPublicationClosure struct {
	generationBody []byte
	generation     pub.TargetGeneration
	planBody       []byte
	plan           pub.Plan
}

// loadHistoricalPublicationClosureAt reads one target-global publication
// closure at an exact canonical commit. All three control documents may be
// absent before the target's first publication; a partial or contradictory
// closure is drift, never evidence that can be skipped.
func loadHistoricalPublicationClosureAt(canonical *state.Store, target string, commit plumbing.Hash) (historicalPublicationClosure, bool, error) {
	return loadHistoricalPublicationClosureAtMode(canonical, target, commit, true)
}

// loadHistoricalPublicationClosureAtForMigration validates every publication
// input except the explicit v1/nonempty purge-plan attestation that the repair
// operation is about to create. It prevents repair from blessing a global
// triplet whose intent-local mirror or content digest was already incomplete.
func loadHistoricalPublicationClosureAtForMigration(canonical *state.Store, target string, commit plumbing.Hash) (historicalPublicationClosure, bool, error) {
	return loadHistoricalPublicationClosureAtMode(canonical, target, commit, false)
}

func loadHistoricalPublicationClosureAtMode(canonical *state.Store, target string, commit plumbing.Hash, requireLegacyAttestation bool) (historicalPublicationClosure, bool, error) {
	var closure historicalPublicationClosure
	generationBody, generationExists, err := readCanonicalBytesAt(canonical, commit, remoteStatePath(target, "generation.json"), 16<<20)
	if err != nil {
		return closure, false, err
	}
	checkpointBody, checkpointExists, err := readCanonicalBytesAt(canonical, commit, remoteStatePath(target, "checkpoint.json"), 16<<20)
	if err != nil {
		return closure, false, err
	}
	planBody, planExists, err := readCanonicalBytesAt(canonical, commit, remoteStatePath(target, "plan.json"), 64<<20)
	if err != nil {
		return closure, false, err
	}
	if !generationExists && !checkpointExists && !planExists {
		return closure, false, nil
	}
	if !generationExists {
		return closure, false, errors.New("historical target generation is missing")
	}
	if !checkpointExists {
		return closure, false, errors.New("historical target checkpoint is missing")
	}

	generation, err := pub.DecodeTargetGeneration(generationBody)
	if err != nil {
		return closure, false, fmt.Errorf("decode canonical target generation at %s: %w", commit, err)
	}
	if string(generation.Target) != target {
		return closure, false, errors.New("historical target generation names a different target")
	}
	checkpoint, err := pub.DecodeCheckpoint(checkpointBody)
	if err != nil || checkpoint.Target != generation.Target || checkpoint.Generation != generation.Generation ||
		checkpoint.ParentGeneration != generation.ParentGeneration || checkpoint.DesiredCommit != generation.DesiredCommit ||
		checkpoint.Phase != pub.PhaseCheckpointCommitted || checkpoint.GenerationSHA256 != digestBytesCLI(generationBody) ||
		checkpoint.ContentManifestSHA256 != generation.ContentManifestSHA256 ||
		!pub.SamePublicationIntent(checkpoint.IntentView, checkpoint.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) {
		return closure, false, errors.Join(err, errors.New("historical target generation/checkpoint closure is invalid"))
	}
	if !planExists {
		return closure, false, errors.New("historical target publication plan is missing")
	}
	plan, err := pub.DecodePlan(planBody)
	if err != nil {
		return closure, false, fmt.Errorf("decode historical target plan: %w", err)
	}
	if requireLegacyAttestation || checkpoint.PlanSHA256 != "" || len(plan.PurgeURLs) == 0 {
		if err := validateCanonicalCheckpointPlanBinding(canonical, target, generation, generationBody, checkpoint, checkpointBody, plan); err != nil {
			return closure, false, errors.Join(err, errors.New("historical target checkpoint does not bind its publication plan"))
		}
	} else if checkpoint.Schema != pub.CheckpointSchemaV1 {
		return closure, false, errors.New("historical target checkpoint lacks a plan binding outside the v1 migration boundary")
	}
	if (len(plan.Objects) != 0 || len(plan.Deletes) != 0) &&
		(plan.CDNBaseURL == "" || len(plan.Verify) != len(plan.Objects)) {
		return closure, false, errors.New("historical target publication plan closure is invalid")
	}
	for _, evidence := range []struct {
		filename string
		body     []byte
		maximum  int64
	}{
		{filename: "generation.json", body: generationBody, maximum: 16 << 20},
		{filename: "checkpoint.json", body: checkpointBody, maximum: 16 << 20},
		{filename: "plan.json", body: planBody, maximum: 64 << 20},
	} {
		intentPath, pathErr := remoteIntentStatePath(target, generation.IntentView, generation.IntentSnapshot, evidence.filename)
		if pathErr != nil {
			return closure, false, pathErr
		}
		intentBody, intentExists, readErr := readCanonicalBytesAt(canonical, commit, intentPath, evidence.maximum)
		if readErr != nil || !intentExists || !bytes.Equal(intentBody, evidence.body) {
			return closure, false, errors.Join(readErr, fmt.Errorf("historical target intent %s evidence is missing or differs from target-global %s", generation.IntentView, evidence.filename))
		}
	}
	manifestSHA, contentExists, err := hashCanonicalPathOptionalAt(canonical, commit, remoteStatePath(target, "content.tsv"))
	if err != nil || !contentExists || manifestSHA != generation.ContentManifestSHA256 {
		return closure, false, errors.Join(err, fmt.Errorf("historical content manifest digest=%s want=%s", manifestSHA, generation.ContentManifestSHA256))
	}
	if err := validateHistoricalCompatibilityPublicationClosure(canonical, commit, generation, plan); err != nil {
		return closure, false, fmt.Errorf("historical compatibility publication closure: %w", err)
	}
	return historicalPublicationClosure{
		generationBody: generationBody, generation: generation,
		planBody: planBody, plan: plan,
	}, true, nil
}

type adoptedImmutableProof struct {
	size   int64
	sha256 string
}

func validateHistoricalDesiredCommit(canonical *state.Store, generation pub.TargetGeneration, stateCommit plumbing.Hash, stateIndex int, historyIndex map[plumbing.Hash]int) error {
	desiredCommit := plumbing.NewHash(generation.DesiredCommit)
	desiredIndex, exists := historyIndex[desiredCommit]
	if desiredCommit.IsZero() || !exists {
		return fmt.Errorf("historical publication at %s names desired commit %s outside canonical HEAD history", stateCommit, generation.DesiredCommit)
	}
	if desiredIndex < stateIndex {
		return fmt.Errorf("historical publication at %s names future desired commit %s", stateCommit, desiredCommit)
	}
	ancestor, err := canonical.IsAncestor(desiredCommit, stateCommit)
	if err != nil {
		return fmt.Errorf("historical publication at %s cannot prove desired commit ancestry %s: %w", stateCommit, desiredCommit, err)
	}
	if !ancestor {
		return fmt.Errorf("historical publication at %s names non-ancestor desired commit %s", stateCommit, desiredCommit)
	}
	return nil
}

// collectHistoricalAdoptedImmutableProofs walks only from the selected source
// state toward older canonical commits. This direction is the key
// anti-forgery boundary: a later publication can never retroactively authorize
// an adopted object in an older restore source.
func collectHistoricalAdoptedImmutableProofs(canonical *state.Store, target string, sourceCommit plumbing.Hash, sourceGeneration uint64) (map[string]adoptedImmutableProof, error) {
	if canonical == nil || sourceCommit.IsZero() || sourceGeneration == 0 {
		return nil, errors.New("historical adopted provenance requires canonical state, source commit, and generation")
	}
	history, err := canonical.History()
	if err != nil {
		return nil, err
	}
	historyIndex := make(map[plumbing.Hash]int, len(history))
	sourceIndex := -1
	for index, commit := range history {
		historyIndex[commit] = index
		if commit == sourceCommit {
			sourceIndex = index
		}
	}
	if sourceIndex < 0 {
		return nil, fmt.Errorf("restore source commit %s is outside canonical HEAD history", sourceCommit)
	}

	proofs := make(map[string]adoptedImmutableProof)
	generationCeiling := sourceGeneration
	seenSource := false
	for offset, commit := range history[sourceIndex:] {
		closure, exists, err := loadHistoricalPublicationClosureAt(canonical, target, commit)
		if err != nil {
			return nil, fmt.Errorf("historical publication closure at %s: %w", commit, err)
		}
		if !exists {
			continue
		}
		stateIndex := sourceIndex + offset
		if err := validateHistoricalDesiredCommit(canonical, closure.generation, commit, stateIndex, historyIndex); err != nil {
			return nil, err
		}
		generation := closure.generation.Generation
		if generation > sourceGeneration || generation > generationCeiling {
			return nil, fmt.Errorf("historical publication generation %d at %s is newer than restore provenance ceiling %d", generation, commit, generationCeiling)
		}
		generationCeiling = generation
		if commit == sourceCommit {
			seenSource = true
			if generation != sourceGeneration {
				return nil, fmt.Errorf("restore source commit generation=%d want=%d", generation, sourceGeneration)
			}
		}
		adopted := make(map[string][]pub.PlannedObject)
		for _, object := range closure.plan.Objects {
			if object.Class == pub.ObjectAdoptedImmutable {
				adopted[object.SourcePath] = append(adopted[object.SourcePath], object)
			}
		}
		if len(adopted) == 0 {
			continue
		}
		content, err := canonical.OpenPathAt(commit, remoteStatePath(target, "content.tsv"))
		if err != nil {
			return nil, fmt.Errorf("open historical content manifest at %s: %w", commit, err)
		}
		reader := manifest.NewReader(content)
		for {
			entry, readErr := reader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = content.Close()
				return nil, fmt.Errorf("read historical content manifest at %s: %w", commit, readErr)
			}
			objects, wanted := adopted[entry.Path]
			if !wanted {
				continue
			}
			for _, object := range objects {
				if entry.Size != object.Size || entry.HashString() != object.SHA256 {
					_ = content.Close()
					return nil, fmt.Errorf("historical adopted object %s is not bound to content manifest at %s", object.RemoteKey, commit)
				}
				proof := adoptedImmutableProof{size: object.Size, sha256: object.SHA256}
				if prior, duplicate := proofs[object.RemoteKey]; duplicate && prior != proof {
					_ = content.Close()
					return nil, fmt.Errorf("historical adopted object %s has conflicting provenance", object.RemoteKey)
				}
				proofs[object.RemoteKey] = proof
			}
			delete(adopted, entry.Path)
		}
		closeErr := content.Close()
		if closeErr != nil {
			return nil, closeErr
		}
		if len(adopted) != 0 {
			for _, objects := range adopted {
				return nil, fmt.Errorf("historical adopted object %s is absent from content manifest at %s", objects[0].RemoteKey, commit)
			}
		}
	}
	if !seenSource {
		return nil, fmt.Errorf("restore source commit %s has no successful target publication closure", sourceCommit)
	}
	return proofs, nil
}

// markHistoricallyAdoptedImmutableObjects carries adoption provenance into a
// forward restore only when the old proof, the reconstructed current plan,
// and a complete current remote inventory all agree on key, size, and digest.
// Explicit absence from a complete inventory is intentionally not drift: a
// legal intervening deletion must be restored by an ordinary PUT.
func markHistoricallyAdoptedImmutableObjects(canonical *state.Store, target string, sourceCommit plumbing.Hash, sourceGeneration uint64, plan *pub.Plan) error {
	if canonical == nil || plan == nil {
		return errors.New("historical adopted immutable classification requires canonical state and a plan")
	}
	proofs, err := collectHistoricalAdoptedImmutableProofs(canonical, target, sourceCommit, sourceGeneration)
	if err != nil {
		return fmt.Errorf("%w: %v", pub.ErrDrift, err)
	}
	if len(proofs) == 0 {
		return nil
	}
	type candidate struct {
		index int
		found bool
	}
	candidates := make(map[string]*candidate)
	for index, object := range plan.Objects {
		if object.Class != pub.ObjectImmutable {
			continue
		}
		proof, exists := proofs[object.RemoteKey]
		if !exists || proof.size != object.Size || proof.sha256 != object.SHA256 {
			continue
		}
		if _, duplicate := candidates[object.RemoteKey]; duplicate {
			return fmt.Errorf("%w: duplicate historical adopted immutable remote key %s", pub.ErrDrift, object.RemoteKey)
		}
		candidates[object.RemoteKey] = &candidate{index: index}
	}
	if len(candidates) == 0 {
		return nil
	}
	coverage, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "inventory.coverage"))
	if err != nil {
		return fmt.Errorf("%w: read historical adopted remote inventory coverage: %v", pub.ErrDrift, err)
	}
	if !exists || string(coverage) == remoteInventoryPartial {
		return nil
	}
	if string(coverage) != remoteInventoryComplete {
		return fmt.Errorf("%w: historical adopted remote inventory coverage is invalid", pub.ErrDrift)
	}
	inventory, inventoryExists, err := openOptionalCanonical(canonical, remoteStatePath(target, "inventory.tsv"))
	if err != nil {
		return fmt.Errorf("%w: open historical adopted remote inventory: %v", pub.ErrDrift, err)
	}
	if !inventoryExists {
		return fmt.Errorf("%w: complete historical adopted remote inventory manifest is missing", pub.ErrDrift)
	}
	reader := manifest.NewReader(inventory)
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = inventory.Close()
			return fmt.Errorf("%w: read historical adopted remote inventory: %v", pub.ErrDrift, readErr)
		}
		candidate, wanted := candidates[entry.Path]
		if !wanted {
			continue
		}
		object := plan.Objects[candidate.index]
		if entry.Size != object.Size || entry.HashString() != object.SHA256 {
			_ = inventory.Close()
			return fmt.Errorf("%w: historical adopted immutable %s disagrees with complete remote inventory", pub.ErrDrift, entry.Path)
		}
		candidate.found = true
	}
	if closeErr := inventory.Close(); closeErr != nil {
		return closeErr
	}
	for _, candidate := range candidates {
		if candidate.found {
			plan.Objects[candidate.index].Class = pub.ObjectAdoptedImmutable
		}
	}
	return nil
}
