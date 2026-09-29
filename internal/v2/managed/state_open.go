package managed

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

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
	store, err := openStateBound(path, state.OpenExisting)
	if errors.Is(err, state.ErrSchemaMigrationRequired) {
		repository := strings.TrimSuffix(filepath.Base(path), ".db")
		return nil, fmt.Errorf("%w; back up the workspace, then run `sow repo migrate %s`", err, repository)
	}
	return store, err
}

func openExistingStateForMigration(path string) (*state.Store, error) {
	return openStateBound(path, func(path string) (*state.Store, error) {
		return state.OpenExistingForMigration(path, true)
	})
}

func openInitializingState(path string) (*state.Store, error) {
	return openStateBound(path, state.OpenInitializing)
}

func openReadOnlyState(path string) (*state.Store, error) {
	return openStateBound(path, state.OpenReadOnly)
}
