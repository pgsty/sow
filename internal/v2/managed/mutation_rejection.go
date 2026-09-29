package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pgsty/sow/internal/v2/state"
)

// finishUnbuiltMutation is a narrow exit for an old deterministic rejection
// or changed configuration. It never rolls back committed Desired data and
// never guesses whether a public build has started from the current state
// alone: recovering replaces that state, so the event history is required.
func finishUnbuiltMutation(ctx context.Context, root, repoName string, store *state.Store, operation state.Operation, manifest mutationManifest, reason string) error {
	if manifest.Build != nil {
		return fmt.Errorf("%w: cannot abandon a mutation with a frozen build plan", ErrIntegrity)
	}
	detail, err := store.GetOperation(ctx, operation.ID)
	if err != nil {
		return err
	}
	applied := false
	for _, event := range detail.Events {
		switch state.OperationState(event.State) {
		case state.OperationApplied:
			applied = true
		case state.OperationBuilt, state.OperationDone, state.OperationDoneDirty:
			return fmt.Errorf("%w: unbuilt mutation has a built or terminal event", ErrIntegrity)
		}
	}
	if err := validateCurrentPublicGeneration(ctx, root, repoName, store); err != nil {
		return err
	}
	if !applied {
		// ApplyDesiredMutation records its event in the same transaction as
		// objects and memberships. Without that event, no new object may exist.
		failed := 0
		for _, item := range detail.Packages {
			if item.Disposition != "excluded" {
				failed++
			}
		}
		result, _ := json.Marshal(map[string]int{"accepted": 0, "failed": failed})
		if err := store.FailOperation(ctx, operation.ID, "rejected", reason, string(result)); err != nil {
			return err
		}
		// Terminal first: cleanup can time out or be interrupted without making
		// recovery depend on bytes that it already deleted.
		return cleanupFailedMutation(ctx, root, repoName, store, operation)
	}
	for dist, desired := range manifest.Desired {
		actual, err := store.MembershipDigests(ctx, dist, false)
		if err != nil || !sameStringSet(actual, desired) {
			return errors.Join(fmt.Errorf("%w: rejected mutation Desired projection differs from journal", ErrIntegrity), err)
		}
	}
	for _, expected := range manifest.Objects {
		actual, err := store.GetPackageObject(ctx, expected.SHA256)
		if err != nil || !sameManagedPackageFacts(expected, actual) || expected.PoolPath != actual.PoolPath {
			return errors.Join(fmt.Errorf("%w: rejected mutation object differs from journal", ErrIntegrity), err)
		}
	}
	verified := map[string]bool{}
	for _, digests := range manifest.Desired {
		for _, digest := range digests {
			if verified[digest] {
				continue
			}
			verified[digest] = true
			object, err := store.GetPackageObject(ctx, digest)
			if err != nil {
				return err
			}
			source, err := availableManagedPackageSource(root, repoName, object)
			if err != nil {
				return err
			}
			opened, err := source.open()
			if err != nil {
				return err
			}
			if err := errors.Join(authenticatePackageFactSource(ctx, opened, object), opened.CloseVerified()); err != nil {
				return fmt.Errorf("%w: rejected mutation payload is not authentic: %v", ErrIntegrity, err)
			}
		}
	}
	var result struct {
		DroppedPending []string `json:"dropped_pending"`
	}
	if err := json.Unmarshal([]byte(detail.Operation.ResultJSON), &result); err != nil {
		return fmt.Errorf("%w: invalid mutation cleanup evidence", ErrIntegrity)
	}
	for _, digest := range result.DroppedPending {
		if !lowercaseSHA256.MatchString(digest) {
			return fmt.Errorf("%w: invalid dropped pending digest", ErrIntegrity)
		}
	}
	if err := cleanupDroppedPending(ctx, root, repoName, store, result.DroppedPending); err != nil {
		return err
	}
	if err := store.RecordOperationMembershipOutcomes(ctx, operation.ID, manifest.Outcomes); err != nil {
		return err
	}
	detailJSON, _ := json.Marshal(map[string]string{"kind": "build_rejected", "reason": reason, "desired": "preserved"})
	if err := store.RecordOperationProgress(ctx, operation.ID, string(detailJSON)); err != nil {
		return err
	}
	if err := store.SetOperationState(ctx, operation.ID, state.OperationDoneDirty, "rejected"); err != nil {
		return err
	}
	return cleanupMutationStage(root, repoName, operation.ID)
}
