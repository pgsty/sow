package managed

import (
	"errors"

	"github.com/pgsty/sow/internal/v2/state"
)

func openStateBound(path string, opener func(string) (*state.Store, error)) (*state.Store, error) {
	if err := verifyActiveWorkspaceRoot(path); err != nil {
		return nil, err
	}
	store, err := opener(path)
	if err != nil {
		return nil, err
	}
	if err := verifyActiveWorkspaceRoot(path); err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return store, nil
}

func openState(path string) (*state.Store, error) {
	return openStateBound(path, state.Open)
}

func openExistingState(path string) (*state.Store, error) {
	return openStateBound(path, state.OpenExisting)
}

func openInitializingState(path string) (*state.Store, error) {
	return openStateBound(path, state.OpenInitializing)
}

func openReadOnlyState(path string) (*state.Store, error) {
	return openStateBound(path, state.OpenReadOnly)
}
