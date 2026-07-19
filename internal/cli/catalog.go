package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

// rebuildCatalogProjection refreshes the disposable query layer only after a
// canonical mutation is durable. Failure never rolls canonical state back;
// replaying the idempotent command rebuilds the cache from the same refs/CAS.
func rebuildCatalogProjection(ctx context.Context, cfg *config.Config, stdout io.Writer) error {
	canonical := state.New(cfg.StatePath())
	head, err := canonical.HeadHash()
	if err != nil {
		return withExitCode(ExitInternal, "read canonical HEAD before SQLite catalog verification: %v", err)
	}
	if err := ensureCatalogProjectionAt(ctx, cfg.StatePath(), head); err != nil {
		return withExitCode(ExitInternal, "rebuild SQLite catalog projection: %v", err)
	}
	stats, err := catalog.Statistics(ctx, cfg.StatePath())
	if err != nil {
		return withExitCode(ExitInternal, "verify SQLite catalog projection: %v", err)
	}
	fmt.Fprintf(stdout, "catalog rebuilt files=%d packages=%d memberships=%d relations=%d provenance=%d\n",
		stats.Files, stats.Packages, stats.Memberships, stats.Relations, stats.Provenance)
	return nil
}

// applyCanonicalState is the only production entry point for a completed
// canonical Store.Apply mutation. It keeps the disposable SQLite projection
// bound to the exact aggregate HEAD without turning projection-neutral serving
// and publication-ledger commits into O(repository-size) rebuilds.
func applyCanonicalState(
	ctx context.Context,
	store *state.Store,
	operation, message string,
	staged map[string]string,
	refs []state.RefUpdate,
	options state.ApplyOptions,
) (plumbing.Hash, bool, error) {
	before, err := store.HeadHash()
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("read canonical HEAD before %s: %w", operation, err)
	}
	if err := beginCatalogProjectionMutation(store.StateDir(), before); err != nil {
		return plumbing.ZeroHash, false, err
	}
	commit, changed, err := store.Apply(ctx, operation, message, staged, refs, options)
	if err != nil {
		// Store.Apply can intentionally stop after its durable Git commit during
		// fault injection or ref recovery. prepareCanonicalState --recover does
		// a full rebuild only after the exact journaled ref vector converges.
		if commit.IsZero() {
			err = errors.Join(err, finishCatalogProjectionMutation(store.StateDir()))
		}
		return commit, changed, err
	}
	after, err := store.HeadHash()
	if err != nil {
		return commit, changed, fmt.Errorf("read canonical HEAD after %s: %w", operation, err)
	}
	affected, err := catalogProjectionAffected(store, before, after, staged, refs, options.DeletePaths)
	if err != nil {
		return commit, changed, fmt.Errorf("classify SQLite catalog impact after %s: %w", operation, err)
	}
	if affected || before.IsZero() {
		if err := catalog.RebuildContext(ctx, store.StateDir()); err != nil {
			return commit, changed, fmt.Errorf("rebuild SQLite catalog after %s: %w", operation, err)
		}
		return commit, changed, finishCatalogProjectionMutation(store.StateDir())
	}
	if err := catalog.AdvanceCanonicalHead(ctx, store.StateDir(), before, after); err == nil {
		return commit, changed, finishCatalogProjectionMutation(store.StateDir())
	}
	// The cache is disposable. Missing, stale, corrupt, or pre-v3 metadata is
	// repaired from canonical refs and CAS instead of weakening the exact CAS.
	if err := catalog.RebuildContext(ctx, store.StateDir()); err != nil {
		return commit, changed, fmt.Errorf("rebuild SQLite catalog after failed head-only advance for %s: %w", operation, err)
	}
	return commit, changed, finishCatalogProjectionMutation(store.StateDir())
}

const catalogProjectionMutationSchema = "sow-catalog-projection-pending/v1"

func catalogProjectionMutationPath(stateDir string) string {
	return filepath.Join(stateDir, "transactions", "catalog-projection.pending")
}

func beginCatalogProjectionMutation(stateDir string, before plumbing.Hash) error {
	directory := filepath.Dir(catalogProjectionMutationPath(stateDir))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create catalog projection transaction directory: %w", err)
	}
	marker := catalogProjectionMutationPath(stateDir)
	if _, err := os.Lstat(marker); err == nil {
		return fmt.Errorf("%w: pending SQLite catalog projection recovery", state.ErrRecoveryRequired)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect catalog projection recovery marker: %w", err)
	}
	temporary, err := os.CreateTemp(directory, "catalog-projection-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	body := catalogProjectionMutationSchema + "\n" + before.String() + "\n"
	if _, err := io.WriteString(temporary, body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, marker); err != nil {
		return err
	}
	keep = true
	return syncCatalogProjectionDirectory(directory)
}

func pendingCatalogProjectionMutation(stateDir string) (bool, error) {
	marker := catalogProjectionMutationPath(stateDir)
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 256 {
		return false, errors.New("catalog projection recovery marker is not a bounded regular file")
	}
	body, err := os.ReadFile(marker)
	if err != nil {
		return false, err
	}
	parts := strings.Split(string(body), "\n")
	if len(parts) != 3 || parts[0] != catalogProjectionMutationSchema || parts[2] != "" {
		return false, errors.New("catalog projection recovery marker is invalid")
	}
	hash := plumbing.NewHash(parts[1])
	if hash.String() != parts[1] {
		return false, errors.New("catalog projection recovery marker has invalid canonical HEAD")
	}
	return true, nil
}

func finishCatalogProjectionMutation(stateDir string) error {
	marker := catalogProjectionMutationPath(stateDir)
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove catalog projection recovery marker: %w", err)
	}
	return syncCatalogProjectionDirectory(filepath.Dir(marker))
}

func syncCatalogProjectionDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}

func catalogProjectionAffected(store *state.Store, before, after plumbing.Hash, staged map[string]string, refs []state.RefUpdate, deleted []string) (bool, error) {
	for _, update := range refs {
		projectionPath, relevant, err := catalogProjectionRefPath(update.Name)
		if err != nil {
			return false, err
		}
		if relevant {
			prior := update.Expected
			target := update.Target
			if update.Delete {
				target = plumbing.ZeroHash
			} else if target.IsZero() {
				target = after
			}
			if prior == target {
				continue
			}
			priorIdentity, priorExists, err := blobIdentityAtOptional(store, prior, projectionPath)
			if err != nil {
				return false, err
			}
			targetIdentity, targetExists, err := blobIdentityAtOptional(store, target, projectionPath)
			if err != nil {
				return false, err
			}
			if priorExists != targetExists || priorIdentity != targetIdentity {
				return true, nil
			}
		}
	}
	paths := make(map[string]struct{}, len(staged)+len(deleted))
	for canonicalPath := range staged {
		if catalogProjectionPath(canonicalPath) {
			paths[canonicalPath] = struct{}{}
		}
	}
	for _, canonicalPath := range deleted {
		if catalogProjectionPath(canonicalPath) {
			paths[canonicalPath] = struct{}{}
		}
	}
	for canonicalPath := range paths {
		beforeIdentity, beforeExists, err := blobIdentityAtOptional(store, before, canonicalPath)
		if err != nil {
			return false, err
		}
		afterIdentity, afterExists, err := blobIdentityAtOptional(store, after, canonicalPath)
		if err != nil {
			return false, err
		}
		if beforeExists != afterExists || beforeIdentity != afterIdentity {
			return true, nil
		}
	}
	return false, nil
}

func blobIdentityAtOptional(store *state.Store, commit plumbing.Hash, canonicalPath string) (state.BlobIdentity, bool, error) {
	if commit.IsZero() {
		return state.BlobIdentity{}, false, nil
	}
	return store.BlobIdentityAt(commit, canonicalPath)
}

func catalogProjectionPath(canonicalPath string) bool {
	return canonicalPath == "config/sow.yaml" ||
		strings.HasPrefix(canonicalPath, "manifests/") ||
		strings.HasPrefix(canonicalPath, "views/") ||
		strings.HasPrefix(canonicalPath, "snapshots/") ||
		strings.HasPrefix(canonicalPath, "provenance/")
}

func catalogProjectionRefPath(name plumbing.ReferenceName) (string, bool, error) {
	parts := strings.Split(name.String(), "/")
	if len(parts) < 4 || parts[0] != "refs" || parts[1] != "sow" {
		return "", false, nil
	}
	switch parts[2] {
	case "repos":
		if len(parts) != 4 {
			return "", false, fmt.Errorf("invalid repository projection ref %s", name)
		}
		return filepath.ToSlash(filepath.Join("manifests", parts[3]+".tsv")), true, nil
	case "views":
		if len(parts) != 7 {
			return "", false, fmt.Errorf("invalid view projection ref %s", name)
		}
		value, err := state.ViewPath(parts[3], parts[4], parts[5], parts[6])
		return value, true, err
	case "snapshots":
		if len(parts) != 7 {
			return "", false, fmt.Errorf("invalid snapshot projection ref %s", name)
		}
		value, err := state.SnapshotPath(parts[3], parts[4], parts[5], parts[6])
		return value, true, err
	default:
		return "", false, nil
	}
}

func ensureCatalogProjectionAt(ctx context.Context, stateDir string, head plumbing.Hash) error {
	if head.IsZero() {
		return catalog.RebuildContext(ctx, stateDir)
	}
	version, versionErr := catalog.Version(ctx, stateDir)
	cacheHead, headErr := catalog.CanonicalHead(ctx, stateDir)
	if versionErr == nil && headErr == nil && version == catalog.SchemaVersion && cacheHead == head {
		return nil
	}
	return catalog.RebuildContext(ctx, stateDir)
}
