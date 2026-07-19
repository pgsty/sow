package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

// projectCanonicalMaterializationLeaves streams one already-closed physical
// owner vector into a manifest. Missing refs are errors here: callers resolve
// the requested leaves first, then materializedRoutePhysicalClosureLeaves
// proves that every mandatory owner coordinate exists before target mutation.
func projectCanonicalMaterializationLeaves(canonical *state.Store, source materializeCanonicalSource, leaves []viewLeaf, destination string) (_ int64, _ int64, resultErr error) {
	if canonical == nil || destination == "" || len(leaves) == 0 {
		return 0, 0, errors.New("physical materialization projection input is unavailable")
	}
	inputs := make([]views.ProjectionInput, 0, len(leaves))
	readers := make([]io.ReadCloser, 0, len(leaves))
	defer func() {
		for _, reader := range readers {
			resultErr = errors.Join(resultErr, reader.Close())
		}
	}()
	for _, leaf := range leaves {
		ref, canonicalPath, commit, err := source.resolveLeaf(canonical, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return 0, 0, err
		}
		if err := validateViewAt(canonical, commit, canonicalPath, leaf, source.Public); err != nil {
			return 0, 0, fmt.Errorf("validate physical owner ref %s: %w", ref, err)
		}
		reader, err := canonical.OpenPathAt(commit, canonicalPath)
		if err != nil {
			return 0, 0, err
		}
		readers = append(readers, reader)
		inputs = append(inputs, views.ProjectionInput{Label: ref.String(), Reader: reader})
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, 0, err
	}
	entries, bytes, projectErr := views.ProjectManifest(inputs, output)
	closeErr := errors.Join(output.Sync(), output.Close())
	for _, reader := range readers {
		closeErr = errors.Join(closeErr, reader.Close())
	}
	readers = nil
	return entries, bytes, errors.Join(projectErr, closeErr)
}

func sameViewLeafSet(left, right []viewLeaf) bool {
	if len(left) != len(right) {
		return false
	}
	keys := make(map[string]int, len(left))
	for _, leaf := range left {
		keys[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)]++
	}
	for _, leaf := range right {
		key := servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)
		keys[key]--
		if keys[key] < 0 {
			return false
		}
	}
	for _, count := range keys {
		if count != 0 {
			return false
		}
	}
	return true
}

// materializedYUMPhysicalClosureLeaves widens only YUM repo+arch ownership.
// Remote APT publication deliberately retains its suite-level selector model,
// while YUM aliases share the exact same repodata directory and can never be
// prepared independently without destructive last-writer-wins behavior.
func materializedYUMPhysicalClosureLeaves(cfg *config.Config, canonical *state.Store, source materializeCanonicalSource, requested []viewLeaf) ([]viewLeaf, error) {
	ordinary := make([]viewLeaf, 0, len(requested))
	yumRequested := make([]viewLeaf, 0, len(requested))
	for _, leaf := range requested {
		if leaf.repo.Type == "yum" {
			yumRequested = append(yumRequested, leaf)
		} else {
			ordinary = append(ordinary, leaf)
		}
	}
	if len(yumRequested) != 0 {
		closed, err := materializedRoutePhysicalClosureLeaves(cfg, canonical, source, yumRequested)
		if err != nil {
			return nil, err
		}
		ordinary = append(ordinary, closed...)
	}
	sort.Slice(ordinary, func(i, j int) bool {
		return servingLeafKey(ordinary[i].repo.ID, ordinary[i].os, ordinary[i].arch) < servingLeafKey(ordinary[j].repo.ID, ordinary[j].os, ordinary[j].arch)
	})
	return ordinary, nil
}

// materializedRoutePhysicalRepos restores canonical repo contracts while
// retaining only the touched YUM architectures. Clearing CLI OS/arch filters
// against this detached slice makes working-tree preparation rebuild the
// complete touched physical owners without widening to another repo or arch.
func materializedRoutePhysicalRepos(cfg *config.Config, leaves []viewLeaf) ([]config.Repo, error) {
	byRepo := make(map[string]map[string]struct{})
	for _, leaf := range leaves {
		arches := byRepo[leaf.repo.ID]
		if arches == nil {
			arches = make(map[string]struct{})
			byRepo[leaf.repo.ID] = arches
		}
		arches[leaf.arch] = struct{}{}
	}
	ids := make([]string, 0, len(byRepo))
	for id := range byRepo {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]config.Repo, 0, len(ids))
	for _, id := range ids {
		repo, exists := cfg.RepoByName(id)
		if !exists {
			return nil, fmt.Errorf("physical materialization repository %s is absent", id)
		}
		if repo.Type == "yum" {
			var arches []string
			for arch := range byRepo[id] {
				arches = append(arches, arch)
			}
			sort.Strings(arches)
			repo.Arches = arches
		}
		result = append(result, repo)
	}
	return result, nil
}

// selectedMaterializationArchiveExact keeps archive selector semantics
// separate from physical owner closure. Payload comes from the originally
// requested refs; generated metadata is retained only below the selector's
// declared replace/upsert scopes (notably selected APT dists plus shared pool
// payload entries already present in requestedPayload).
func selectedMaterializationArchiveExact(cfg *config.Config, source materializeCanonicalSource, requested []viewLeaf, requestedPayload string, metadata []string, txDir string) (string, error) {
	selection, err := directMaterializationSelection(cfg, requested, source)
	if err != nil {
		return "", err
	}
	scopes := append(append([]string(nil), selection.Replace...), selection.Upsert...)
	parts := []string{requestedPayload}
	for index, input := range metadata {
		filtered := filepath.Join(txDir, fmt.Sprintf("archive-requested-metadata-%03d.tsv", index))
		if _, err := filterManifestFile(input, filtered, func(entry manifest.Entry) bool {
			for _, scope := range scopes {
				if pathWithin(entry.Path, scope) {
					return true
				}
			}
			return false
		}); err != nil {
			return "", err
		}
		parts = append(parts, filtered)
	}
	result := filepath.Join(txDir, "materialized-requested-archive-exact.tsv")
	if err := mergePublicationManifests(parts, result, txDir); err != nil {
		return "", err
	}
	return result, nil
}

// directPhysicalOwnerMaterializationSelection upgrades a mutable ordinary APT
// selector from suite metadata + pool upsert to an exact repo-wide owner
// replacement. The caller has already projected every current ref for that
// touched owner, so retaining an unreferenced historical pool file would make
// the new route receipt unreplayable. YUM/asset scopes already coincide with
// their physical ownership units and retain the ordinary selector mapping.
func directPhysicalOwnerMaterializationSelection(cfg *config.Config, leaves []viewLeaf, source materializeCanonicalSource) (manifestSelectionScopes, error) {
	selection, err := directMaterializationSelection(cfg, leaves, source)
	if err != nil || source.Snapshot {
		return selection, err
	}
	aptRoots := make(map[string]struct{})
	for _, leaf := range leaves {
		repo, exists := cfg.RepoByName(leaf.repo.ID)
		if !exists {
			return manifestSelectionScopes{}, fmt.Errorf("repository %s is absent from canonical configuration", leaf.repo.ID)
		}
		if repo.Type == "apt" {
			aptRoots[repo.Path] = struct{}{}
		}
	}
	if len(aptRoots) == 0 {
		return selection, nil
	}
	keep := func(scope string) bool {
		for root := range aptRoots {
			if pathWithin(scope, root) {
				return false
			}
		}
		return true
	}
	replace := selection.Replace[:0]
	for _, scope := range selection.Replace {
		if keep(scope) {
			replace = append(replace, scope)
		}
	}
	upsert := selection.Upsert[:0]
	for _, scope := range selection.Upsert {
		if keep(scope) {
			upsert = append(upsert, scope)
		}
	}
	for root := range aptRoots {
		replace = append(replace, root)
	}
	selection.Replace, selection.Upsert, err = normalizeManifestSelectionScopes(replace, upsert)
	return selection, err
}
