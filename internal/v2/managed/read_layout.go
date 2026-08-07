package managed

import (
	"context"

	"github.com/pgsty/sow/internal/v2/state"
)

// repositoryReadLayout classifies both the byte-for-byte frozen v0.2 schema
// and a current-schema Repository that was safely returned to C2 before
// commit_intent.  The latter is intentionally readable but remains unwritable
// until the operator runs the explicit migration again.
type repositoryReadLayout struct {
	FrozenC2      bool
	Identity      state.RepositoryIdentity
	IdentityErr   error
	Transition    *C2ToSingleTransition
	TransitionErr error
	Control       *state.LayoutTransitionControl
	ControlErr    error
}

func inspectRepositoryReadLayout(ctx context.Context, root, repoName string, store *state.Store) repositoryReadLayout {
	if store.SchemaVersion() == 6 {
		return repositoryReadLayout{
			FrozenC2: true,
			Identity: state.RepositoryIdentity{LayoutVersion: state.LayoutC2V1},
		}
	}
	result := repositoryReadLayout{}
	result.Identity, result.IdentityErr = store.RepositoryIdentity(ctx)
	result.Transition, _, result.TransitionErr = loadTransitionJournal(root, repoName)
	result.Control, result.ControlErr = store.LayoutTransitionControl(ctx)
	result.FrozenC2 = result.IdentityErr == nil && result.Identity.LayoutVersion == state.LayoutC2V1 &&
		result.Transition == nil && result.TransitionErr == nil && result.Control == nil && result.ControlErr == nil
	return result
}

func (layout repositoryReadLayout) transitionActive() bool {
	if layout.FrozenC2 {
		return false
	}
	return layout.IdentityErr == nil && layout.Identity.LayoutVersion != state.LayoutSinglePayloadV1 ||
		layout.Transition != nil || layout.TransitionErr != nil || layout.Control != nil || layout.ControlErr != nil
}
